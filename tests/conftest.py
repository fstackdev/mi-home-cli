import base64
import json
from collections import deque

import pytest
import requests

from mi_home_cli.auth import Session
from mi_home_cli.storage import Store
from mi_home_cli.transport import Transport

TOKEN = "ab" * 16
SECURITY = base64.b64encode(bytes(range(16))).decode()
SERVICE = "test-service-credential"


def response(data=None, *, text=None, status=200, headers=None, cookies=None):
    result = requests.Response()
    result.status_code = status
    result._content = (text if text is not None else json.dumps(data or {})).encode()
    result.headers.update(headers or {})
    result.url = "https://account.xiaomi.com/pass/serviceLoginAuth2/end"
    result.cookies = requests.cookies.cookiejar_from_dict(cookies or {})
    return result


class FakeHTTP(Transport):
    def __init__(self, *responses):
        super().__init__()
        self.responses = deque(responses)
        self.calls = []
        self.session.request = self.send

    def send(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if not self.responses:
            raise AssertionError("Unexpected extra HTTP request")
        item = self.responses.popleft()
        if isinstance(item, Exception):
            raise item
        for cookie in item.cookies:
            self.session.cookies.set(cookie.name, cookie.value, domain=".sts.api.io.mi.com")
        return item


class UI:
    def __init__(self, *answers):
        self.answers = iter(answers)
        self.messages = []
        self.qr_seen = False

    def text(self, prompt):
        return next(self.answers)

    def secret(self, prompt):
        return next(self.answers)

    def message(self, value):
        self.messages.append(value)

    def qr(self, value):
        self.qr_seen = True


@pytest.fixture(autouse=True)
def offline(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        raise AssertionError("Tests must not access a real Xiaomi account or network")

    monkeypatch.setattr(requests.sessions.Session, "request", forbidden)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))


@pytest.fixture
def store():
    return Store()


@pytest.fixture
def session():
    return Session("fake-user", SECURITY, SERVICE)


@pytest.fixture
def device():
    return {
        "did": "123",
        "name": "Office heater",
        "model": "zhimi.heater.mc2",
        "localip": "192.0.2.10",
        "mac": "00:00:00:00:00:01",
        "token": TOKEN,
        "isOnline": True,
        "extra": {"fw_version": "test"},
        "password": "never-export-this",
        "latitude": "never-export-this",
    }
