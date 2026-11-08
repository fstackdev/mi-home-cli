"""Headless CLI. Secrets appear only in explicit user-requested output."""

import argparse
import getpass
import json
import sys
import warnings
from pathlib import Path

import qrcode

from . import __version__
from .auth import Authenticator, Session
from .cloud import Cloud, regions_for
from .errors import MiHomeError
from .storage import Store, write_private
from .transport import REGIONS, Transport


class Terminal:
    def message(self, text):
        print(text, file=sys.stderr)

    def text(self, prompt):
        print(prompt, end="", file=sys.stderr, flush=True)
        return input().strip()

    def secret(self, prompt):
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            try:
                return getpass.getpass(prompt)
            except getpass.GetPassWarning:
                raise MiHomeError(
                    "Cannot hide input on this terminal. Use an interactive SSH TTY."
                ) from None

    def qr(self, url):
        self.message(
            "Scan with Xiaomi Home and approve login. This QR is a short-lived credential."
        )
        qr = qrcode.QRCode(border=2)
        qr.add_data(url)
        qr.print_ascii(out=sys.stderr, invert=True)


def parser():
    root = argparse.ArgumentParser(description="Read-only Xiaomi Cloud device/token discovery.")
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)
    login = commands.add_parser("login", help="Authenticate interactively on this terminal")
    login.add_argument("--method", choices=("qr", "password"), default="qr")
    login.add_argument(
        "--region", choices=REGIONS, default="de", help="Default region (de: Europe)"
    )
    commands.add_parser(
        "logout", help="Delete local session and CAPTCHA; does not revoke cloud sessions"
    )
    devices = commands.add_parser("devices", help="Read devices from Xiaomi Cloud")
    actions = devices.add_subparsers(dest="action", required=True)
    for name in ("list", "show", "export"):
        command = actions.add_parser(name)
        command.add_argument(
            "--region", choices=(*REGIONS, "all"), help="Cloud region or all regions"
        )
        command.add_argument("--model", help="Case-insensitive model substring")
        command.add_argument("--name", help="Case-insensitive name substring")
        if name == "show":
            command.add_argument("did")
            command.add_argument(
                "--reveal-token", action="store_true", help="Explicitly reveal this device's token"
            )
            command.add_argument(
                "--homey", action="store_true", help="Show IP/token settings and missing-data hints"
            )
        if name in ("list", "show"):
            command.add_argument(
                "--json",
                action="store_true",
                help="JSON (token is null unless explicitly revealed)",
            )
        if name == "export":
            command.add_argument("--format", choices=("json",), default="json")
            command.add_argument(
                "--include-secrets",
                action="store_true",
                help="Explicitly allow full tokens in export",
            )
            command.add_argument(
                "--output", type=Path, help="New file, mode 0600; existing files are refused"
            )
    return root


def table(rows: list[dict]):
    keys = ("did", "name", "model", "ip", "mac", "region", "token")
    values = [
        [str(row.get(key) if row.get(key) is not None else "-") for key in keys] for row in rows
    ]
    widths = [
        max(len(key), *(len(row[i]) for row in values)) if values else len(key)
        for i, key in enumerate(keys)
    ]
    print("  ".join(key.upper().ljust(width) for key, width in zip(keys, widths, strict=True)))
    for row in values:
        print("  ".join(value.ljust(width) for value, width in zip(row, widths, strict=True)))


def run(args, store: Store, ui: Terminal) -> int:
    if args.command == "logout":
        store.logout()
        ui.message("Local session removed. Xiaomi cloud sessions are not remotely revoked.")
        return 0
    if args.command == "login":
        if not sys.stdin.isatty() or not sys.stderr.isatty():
            raise MiHomeError(
                "Login needs an interactive terminal. SSH to the Pi and run this command yourself."
            )
        with store.login_guard():
            http = Transport()
            try:
                auth = Authenticator(http, store, ui)
                session = getattr(auth, args.method)(args.region)
                store.save(session.to_dict())
            finally:
                http.close()
        ui.message(
            "Authentication completed; session saved privately. Run 'mi-home-cli devices list'."
        )
        return 0
    session = Session(**store.load())
    regions = regions_for(args.region or session.region)
    http = Transport()
    try:
        cloud = Cloud(http, session)
        # Fail on any region error so scripts never mistake a partial scan for a complete one.
        found = []
        for region in regions:
            ui.message(f"Reading Xiaomi region {region}...")
            try:
                found.extend(cloud.devices(region))
            except MiHomeError as error:
                raise MiHomeError(f"Region {region}: {error}") from None
    finally:
        http.close()
    if args.model:
        found = [d for d in found if args.model.casefold() in (d.model or "").casefold()]
    if args.name:
        found = [d for d in found if args.name.casefold() in (d.name or "").casefold()]
    if args.action == "show":
        found = [d for d in found if d.did == args.did]
        if not found:
            raise MiHomeError("Device not found. Check DID and filters, or try --region all.")
        if len(found) != 1:
            raise MiHomeError("DID exists in multiple regions. Specify --region to select one.")
    reveal = getattr(args, "reveal_token", False) or getattr(args, "include_secrets", False)
    output = [device.public(reveal=reveal) for device in found]
    if args.action == "export" or getattr(args, "json", False):
        payload = (
            json.dumps(output[0] if args.action == "show" else output, indent=2, ensure_ascii=False)
            + "\n"
        )
        if getattr(args, "output", None):
            write_private(args.output, payload.encode())
            ui.message("Export saved with mode 0600.")
        else:
            print(payload, end="")
    elif args.action == "show":
        for key, value in output[0].items():
            if key == "token":
                value = value or (
                    "[hidden; use --reveal-token]" if found[0].token else "[unavailable]"
                )
            print(f"{key}: {value if value is not None else '-'}")
        if args.homey:
            ui.message(
                "Homey: use IP and the 32-character token above in the Xiaomi miIO device pairing."
            )
            if not found[0].token:
                ui.message(
                    "No local miIO token returned. Shared/BLE/cloud-only devices may not expose one."
                )
            if not found[0].ip:
                ui.message(
                    "No cloud IP returned. Find the device's current address in your router's DHCP leases."
                )
    else:
        for device, row in zip(found, output, strict=True):
            row["token"] = "[hidden]" if device.token else "[unavailable]"
        table(output)
        if not found:
            ui.message("No devices matched. Check Xiaomi Home account/region, or try --region all.")
    return 0


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        return run(args, Store(), Terminal())
    except MiHomeError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, KeyError):
        # Never print exception strings: libraries can embed URLs, bodies or credentials.
        print(
            "Error: local state, output path or Xiaomi response is invalid. Check permissions or log in again.",
            file=sys.stderr,
        )
        return 1
    except (KeyboardInterrupt, EOFError):
        print("Cancelled.", file=sys.stderr)
        return 130
