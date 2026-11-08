import json
import os
import stat

import pytest

from mi_home_cli.cli import main
from mi_home_cli.cloud import Device
from mi_home_cli.errors import RateLimitError, StorageError
from mi_home_cli.storage import Store, write_private

from .conftest import SERVICE, TOKEN


def test_private_atomic_session_and_logout(store, session):
    store.save(session.to_dict())
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o700
    assert stat.S_IMODE((store.path / "session.json").stat().st_mode) == 0o600
    assert store.load()["service_token"] == SERVICE
    store.logout()
    assert not (store.path / "session.json").exists()


def test_insecure_session_refused(store, session):
    store.save(session.to_dict())
    os.chmod(store.path / "session.json", 0o644)
    with pytest.raises(StorageError):
        store.load()


def test_directory_symlink_refused(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(StorageError):
        Store(link).prepare()


def test_export_is_private_no_overwrite_no_symlinks(tmp_path):
    path = tmp_path / "export.json"
    write_private(path, b"private")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        write_private(path, b"replacement")
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(FileExistsError):
        write_private(link, b"replacement")
    assert path.read_bytes() == b"private"


def test_login_lock_and_cooldown(store):
    with store.login_guard():
        with pytest.raises(RateLimitError, match="Another login"):
            with store.login_guard():
                pytest.fail("concurrent login was allowed")
    store.logout()
    with pytest.raises(RateLimitError, match="cooldown"):
        with store.login_guard():
            pytest.fail("cooldown bypassed")


@pytest.mark.parametrize(
    "command",
    [
        [],
        ["login"],
        ["logout"],
        ["devices"],
        ["devices", "list"],
        ["devices", "show"],
        ["devices", "export"],
    ],
)
def test_every_help_without_account(command, capsys):
    with pytest.raises(SystemExit) as result:
        main([*command, "--help"])
    assert result.value.code == 0
    assert "usage:" in capsys.readouterr().out


def test_login_requires_tty(capsys):
    assert main(["login"]) == 1
    assert "interactive terminal" in capsys.readouterr().err


def test_all_nonlogin_commands_without_session_are_safe(capsys):
    for command in (["devices", "list"], ["devices", "show", "123"], ["devices", "export"]):
        assert main(command) == 1
        assert "No saved session" in capsys.readouterr().err
    assert main(["logout"]) == 0


@pytest.mark.parametrize(
    "command",
    [
        ["devices", "list"],
        ["devices", "list", "--json"],
        ["devices", "show", "123"],
        ["devices", "show", "123", "--json"],
        ["devices", "export"],
    ],
)
def test_default_cli_never_reveals_tokens(command, store, session, device, monkeypatch, capsys):
    store.save(session.to_dict())
    monkeypatch.setattr(
        "mi_home_cli.cli.Cloud.devices", lambda *args: [Device.from_cloud(device, "de")]
    )
    assert main(command) == 0
    captured = capsys.readouterr()
    assert TOKEN not in captured.out + captured.err
    assert SERVICE not in captured.out + captured.err


def test_explicit_reveal_homey_and_export(store, session, device, monkeypatch, tmp_path, capsys):
    store.save(session.to_dict())
    monkeypatch.setattr(
        "mi_home_cli.cli.Cloud.devices", lambda *args: [Device.from_cloud(device, "de")]
    )
    assert main(["devices", "show", "123", "--homey", "--reveal-token"]) == 0
    assert TOKEN in capsys.readouterr().out
    path = tmp_path / "private.json"
    assert main(["devices", "export", "--include-secrets", "--output", str(path)]) == 0
    assert json.loads(path.read_text())[0]["token"] == TOKEN
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_case_insensitive_filters_and_all_region_scan(store, session, device, monkeypatch, capsys):
    store.save(session.to_dict())
    seen = []

    def devices(self, region):
        seen.append(region)
        return [Device.from_cloud(device, region)] if region == "de" else []

    monkeypatch.setattr("mi_home_cli.cli.Cloud.devices", devices)
    assert (
        main(
            [
                "devices",
                "list",
                "--region",
                "all",
                "--model",
                "HEATER",
                "--name",
                "OFFICE",
                "--json",
            ]
        )
        == 0
    )
    assert len(seen) == 8
    assert json.loads(capsys.readouterr().out)[0]["did"] == "123"


def test_json_not_found_no_partial_output(store, session, device, monkeypatch, capsys):
    store.save(session.to_dict())
    monkeypatch.setattr("mi_home_cli.cli.Cloud.devices", lambda *args: [])
    assert main(["devices", "show", "123", "--json"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Device not found" in captured.err


def test_exception_text_is_not_exposed(monkeypatch, capsys):
    def fail(*args):
        raise ValueError(TOKEN)

    monkeypatch.setattr("mi_home_cli.cli.Store.load", fail)
    assert main(["devices", "list"]) == 1
    captured = capsys.readouterr()
    assert TOKEN not in captured.err + captured.out
