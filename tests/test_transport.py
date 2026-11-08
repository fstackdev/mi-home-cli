import logging

import pytest
import requests

from mi_home_cli.errors import AuthenticationError, NetworkError, ProtocolError, RateLimitError
from mi_home_cli.transport import parse_json, trusted_url

from .conftest import SERVICE, FakeHTTP, response


@pytest.mark.parametrize(
    "url",
    [
        "http://account.xiaomi.com/a",
        "https://account.xiaomi.com.evil.invalid/a",
        "https://other.invalid",
        "https://account.xiaomi.com:444/a",
        "https://name:password@account.xiaomi.com/a",
        "https://account.xiaomi.com/#fragment",
        "https://account.xiaomi.com:invalid",
        "/relative",
        None,
    ],
)
def test_untrusted_destinations(url):
    with pytest.raises(ProtocolError):
        trusted_url(url)


def test_redirect_checked_before_second_request():
    http = FakeHTTP(response(status=302, headers={"Location": "https://evil.invalid/"}))
    with pytest.raises(ProtocolError):
        http.request("GET", "https://account.xiaomi.com/test")
    assert len(http.calls) == 1


def test_tls_timeout_and_body_not_redirected():
    http = FakeHTTP(response(status=302, headers={"Location": "https://sts.api.io.mi.com/sts"}))
    with pytest.raises(ProtocolError):
        http.request("POST", "https://account.xiaomi.com/test", data={"password": SERVICE})
    assert len(http.calls) == 1
    assert http.calls[0][2]["verify"] is True
    assert http.calls[0][2]["timeout"] == (10, 30)
    assert http.session.trust_env is False


def test_safe_relative_redirect():
    http = FakeHTTP(response(status=302, headers={"Location": "/next"}), response({"ok": True}))
    assert http.json("GET", "https://account.xiaomi.com/test")["ok"]
    assert http.calls[-1][1] == "https://account.xiaomi.com/next"


@pytest.mark.parametrize(
    ("item", "error"),
    [
        (requests.exceptions.Timeout(SERVICE), NetworkError),
        (requests.exceptions.ConnectionError(SERVICE), NetworkError),
        (requests.exceptions.SSLError(SERVICE), NetworkError),
        (response(status=429, text=SERVICE), RateLimitError),
        (response(status=401, text=SERVICE), AuthenticationError),
        (response(status=403, text=SERVICE), AuthenticationError),
        (response(status=503, text=SERVICE), NetworkError),
    ],
)
def test_errors_and_logs_never_contain_response_or_exception_secrets(item, error, caplog):
    caplog.set_level(logging.DEBUG)
    http = FakeHTTP(item)
    with pytest.raises(error) as caught:
        http.request("GET", "https://account.xiaomi.com/test")
    assert SERVICE not in str(caught.value)
    assert SERVICE not in caplog.text
    assert len(http.calls) == 1


@pytest.mark.parametrize("text", ["invalid-secret", "[]", "null", "42"])
def test_unexpected_json_sanitized(text):
    with pytest.raises(ProtocolError) as error:
        parse_json(text)
    assert text not in str(error.value)


def test_prefixed_json():
    assert parse_json('&&&START&&&{"code":0}') == {"code": 0}


def test_redirect_limit():
    http = FakeHTTP(*(response(status=302, headers={"Location": "/loop"}) for _ in range(8)))
    with pytest.raises(ProtocolError):
        http.request("GET", "https://account.xiaomi.com/loop")
    assert len(http.calls) == 8
