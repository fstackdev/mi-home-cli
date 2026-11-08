# mi-home-cli

Read-only Xiaomi Cloud device discovery for Linux, Raspberry Pi and SSH. Retrieve device
IDs, models, local IP addresses, MAC addresses and local miIO tokens without Windows,
macOS, Docker, a desktop or a background service. Python 3.11+; MIT licensed.

## Install

Use a dedicated virtual environment. Do not use `sudo pip` or modify system Python.

```sh
git clone https://github.com/fstackdev/mi-home-cli.git "$HOME/mi-home-cli"
python3 -m venv "$HOME/.local/share/mi-home-cli/venv"
"$HOME/.local/share/mi-home-cli/venv/bin/python" -m pip install "$HOME/mi-home-cli"
mkdir -p "$HOME/.local/bin"
ln -s "$HOME/.local/share/mi-home-cli/venv/bin/mi-home-cli" "$HOME/.local/bin/mi-home-cli"
export PATH="$HOME/.local/bin:$PATH"
mi-home-cli --help
```

If `venv` is unavailable, ask your system administrator to install the matching
`python3-venv` OS package. The installer does not change existing services or containers.
If `~/.local/bin/mi-home-cli` already exists, inspect it before creating a link.

## Login directly on the Pi

```sh
mi-home-cli login --region de
# Alternative, with a hidden password prompt:
mi-home-cli login --method password --region de
```

Run this yourself in an interactive terminal, including an SSH session. Never give an
agent your Xiaomi password, CAPTCHA, 2FA code, session or device token. Default login
draws a QR in the terminal: scan it using Xiaomi Home and approve the login. A QR is a
short-lived credential; do not paste it into an issue or send it to someone else.

The password is never stored or accepted as a command-line argument. Password login
supports CAPTCHA and email/SMS 2FA when Xiaomi advertises those methods. CAPTCHA is
saved temporarily as a private image; copy it to your own computer using `scp` and view
it there, then enter the answer in the Pi terminal. The Pi itself requires no GUI.
Unrecognized account-verification flows fail with a safe message; use QR login or
resolve the account challenge in Xiaomi's own app. Each challenge allows at most three
submissions, each login is locked against concurrent attempts, and attempts have a
30-second cooldown. QR polling is capped at 180 seconds / 36 requests.

European QR login requires version 0.1.1 or later. Version 0.1.0 incorrectly rejected
the European account/polling hosts before displaying the QR; follow the update commands
below if you encounter that error.

## Find devices

```sh
mi-home-cli devices list
mi-home-cli devices list --region all
mi-home-cli devices list --model zhimi.heater.mc2
mi-home-cli devices list --name heater --json
mi-home-cli devices show DEVICE_DID
mi-home-cli devices show DEVICE_DID --homey --reveal-token
```

`de` is the European server; other servers are `cn`, `us`, `ru`, `tw`, `sg`, `in`, `i2`.
Use the same account and region as Xiaomi Home. The default is saved at login; override
it per command with `--region`. `--region all` searches all eight sequentially with one
session. A failed region fails the command without emitting a partial device list.
Specify a region if the same DID appears in more than one region. Filters are
case-insensitive substrings. No device list or device token is cached on disk.

Table output hides all tokens. JSON uses `"token": null` plus `token_available` unless
explicitly revealed. `show --json --reveal-token` reveals only the selected device.
Output also includes online state and firmware when available. Raw cloud responses,
Wi-Fi credentials, coordinates and unrecognized extra fields are never exported.

## Homey Pro / Mi Smart Space Heater S

```sh
mi-home-cli devices list --region all --model zhimi.heater.mc2
mi-home-cli devices show DEVICE_DID --region de --homey --reveal-token
```

In Homey's Xiaomi miIO app pairing, enter the reported IP and 32-character token for
the corresponding heater driver. Give the heater a DHCP reservation so the IP remains
stable. This utility retrieves credentials; it does not pair Homey or prove local LAN
connectivity. Homey and the heater need network reachability. If Xiaomi reports no IP,
check your router's DHCP leases. BLE, shared and cloud-only devices may have no local
token; resetting/re-pairing a device can change its token.

## JSON export

```sh
# Redacted, suitable for scripts:
mi-home-cli devices export --format json
# Explicit secret export into a NEW private file (0600):
mi-home-cli devices export --include-secrets --output "$HOME/mi-home-private.json"
```

`--include-secrets` is the explicit authorization; it does not require another prompt.
Without `--output`, JSON is written to stdout, so redirects inherit your shell's umask.
Use `--output` for secret files: existing files and symbolic links are refused.
Keep exports on your own machine. Do not attach them to GitHub, CI, Work or support logs.

## State and security

Minimal cloud session credentials are stored under
`${XDG_STATE_HOME:-$HOME/.local/state}/mi-home-cli`, directory mode 0700, file mode 0600.
The password, password hash, full cookie jar and device tokens are not persisted.
Sessions are written atomically. Files must be owned by the current user. Local
session permissions are validated before loading. No telemetry or diagnostic payload
logging exists; network errors and exceptions are sanitized. TLS certificate validation
is always on. Proxy, `.netrc` and CA override environment variables are ignored.

The RC4/SHA-1 request protocol and MD5 password challenge are Xiaomi compatibility
requirements inside verified TLS; they are not used for local password storage.
Only authentication and three discovery endpoints are implemented. No device control,
IR, BLE-key retrieval, MCP server or remote telemetry is included.

```sh
mi-home-cli logout
```

Logout deletes local credentials and CAPTCHA. It does not revoke Xiaomi cloud sessions,
erase your explicit exports or securely erase filesystem snapshots. The login cooldown
file remains. Use Xiaomi account security settings to revoke sessions if needed.

## Update and uninstall

```sh
git -C "$HOME/mi-home-cli" pull --ff-only
"$HOME/.local/share/mi-home-cli/venv/bin/python" -m pip install --upgrade "$HOME/mi-home-cli"
```

To remove: run `mi-home-cli logout`, remove the symlink you created in `~/.local/bin`,
then remove the dedicated `~/.local/share/mi-home-cli/venv` and source checkout. Remove
the private state directory and any explicit exports separately if desired. Never
remove a pre-existing directory or launcher belonging to another application.

## Development and limitations

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/pytest --cov=mi_home_cli --cov-report=term-missing
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/bandit -q -r src
.venv/bin/detect-secrets scan --no-verify
.venv/bin/pip-audit
.venv/bin/python -m build
```

CI runs offline account-free tests on Python 3.11–3.14, lint, Bandit, dependency
auditing and a tracked-file secret scan. Tests block accidental live network calls. See
[research](docs/research.md) for provenance and licensing, and
[validation](docs/validation.md) for what has actually been tested.

Xiaomi's unofficial API can change or reject a client, account, region or data-center
IP. QR and password/2FA flows are mock-tested; **a successful live account login and
device retrieval must be confirmed by the user on the Pi**. Some device types return
no miIO token. Accounts over 300 homes or homes over 200 devices fail explicitly rather
than silently producing a truncated list. This MVP does not implement pagination for
those very large accounts. An unsupported legacy endpoint falls back to v2 discovery;
other discovery failures fail explicitly rather than claiming an incomplete list is complete.
