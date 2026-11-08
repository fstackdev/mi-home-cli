"""Private state, atomic session writes, exclusive exports and a login cooldown."""

import fcntl
import json
import os
import stat
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from .errors import AuthenticationError, RateLimitError, StorageError


def state_path() -> Path:
    base = os.environ.get("XDG_STATE_HOME")
    return (Path(base) if base else Path.home() / ".local/state") / "mi-home-cli"


def private_directory(path: Path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise StorageError("State directory must be a real directory owned by the current user.")
    os.chmod(path, 0o700)


def write_private(path: Path, content: bytes, *, replace=False):
    """Caller supplies a trusted parent; export paths must have an existing parent."""
    if replace:
        fd, temp = tempfile.mkstemp(prefix=".session-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            if path.is_symlink():
                raise StorageError("Refusing to replace a symbolic link.")
            os.replace(temp, path)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)


class Store:
    def __init__(self, path: Path | None = None):
        self.path = path if path is not None else state_path()

    def prepare(self):
        private_directory(self.path)

    def save(self, session: dict):
        self.prepare()
        write_private(self.path / "session.json", json.dumps(session).encode(), replace=True)

    def load(self) -> dict:
        self.prepare()
        try:
            fd = os.open(self.path / "session.json", os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            raise AuthenticationError("No saved session. Run 'mi-home-cli login' first.") from None
        with os.fdopen(fd) as handle:
            info = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise StorageError("Session must be a regular file owned by you with mode 0600.")
            try:
                result = json.load(handle)
            except ValueError:
                raise AuthenticationError("Saved session is invalid. Log in again.") from None
        required = ("user_id", "ssecurity", "service_token", "region")
        if not isinstance(result, dict) or not all(
            isinstance(result.get(k), str) and result[k] for k in required
        ):
            raise AuthenticationError("Saved session is incomplete. Log in again.")
        return result

    def logout(self):
        self.prepare()
        for name in ("session.json", "captcha.png"):
            (self.path / name).unlink(missing_ok=True)

    @contextmanager
    def login_guard(self):
        self.prepare()
        fd = os.open(self.path / "login.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "r+") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise StorageError("Invalid login lock file.")
            os.fchmod(handle.fileno(), 0o600)
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RateLimitError(
                    "Another login is running. Finish or cancel it first."
                ) from None
            value = handle.read()
            try:
                last = float(value) if value else 0
            except ValueError:
                last = time.time()
            if time.time() - last < 30:
                raise RateLimitError("Login cooldown: wait 30 seconds between login attempts.")
            handle.seek(0)
            handle.truncate()
            handle.write(str(time.time()))
            handle.flush()
            yield
