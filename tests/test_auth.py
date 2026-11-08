import json

import pytest
import requests

from mi_home_cli.auth import Authenticator
from mi_home_cli.errors import AuthenticationError, ProtocolError, RateLimitError

from .conftest import SECURITY, SERVICE, UI, FakeHTTP, response


def completion():
    return {
        "code": 0,
        "userId": "test-user",
        "ssecurity": SECURITY,
        "location": "https://sts.api.io.mi.com/sts?ticket=private",
    }


def test_qr_success_without_persisting_pass_token(store):
    http = FakeHTTP(
        response(
            {
                "loginUrl": "https://account.xiaomi.com/qr?id=private",
                "lp": "https://account.xiaomi.com/longPolling/lp",
                "timeout": 30,
            }
        ),
        response(completion() | {"passToken": "not-persisted"}),
        response(cookies={"serviceToken": SERVICE}),
    )
    ui = UI()
    session = Authenticator(http, store, ui).qr("de")
    store.save(session.to_dict())
    assert ui.qr_seen
    assert session.service_token == SERVICE
    assert "not-persisted" not in (store.path / "session.json").read_text()
    assert SERVICE not in repr(session)


def test_european_qr_bootstrap_and_polling(store):
    # Hostnames observed on Pi4; ticket values here are synthetic and never real.
    poll_url = "https://eu.lp.account.xiaomi.com/longPolling/lp?ticket=private"
    http = FakeHTTP(
        response(
            {
                "loginUrl": "https://eu.account.xiaomi.com/longPolling/login?ticket=private",
                "lp": poll_url,
                "timeout": 30,
            }
        ),
        response(completion()),
        response(cookies={"serviceToken": SERVICE}),
    )
    ui = UI()
    session = Authenticator(http, store, ui).qr("de")
    assert ui.qr_seen
    assert session.service_token == SERVICE
    assert http.calls[1][1] == poll_url
    assert all(call[2]["verify"] is True for call in http.calls)
    assert ui.messages == []
    assert not (store.path / "session.json").exists()


@pytest.mark.parametrize("field", ["loginUrl", "lp"])
def test_qr_unlisted_host_rejected_before_render_or_poll(store, field):
    bootstrap = {
        "loginUrl": "https://eu.account.xiaomi.com/longPolling/login?ticket=private",
        "lp": "https://eu.lp.account.xiaomi.com/longPolling/lp?ticket=private",
        "timeout": 30,
    }
    bootstrap[field] = "https://unlisted.account.xiaomi.com/should-not-run?ticket=private"
    http = FakeHTTP(response(bootstrap))
    ui = UI()
    with pytest.raises(ProtocolError) as caught:
        Authenticator(http, store, ui).qr("de")
    assert not ui.qr_seen
    assert len(http.calls) == 1
    assert "ticket=private" not in str(caught.value)


def test_qr_timeout_is_bounded(store, monkeypatch):
    http = FakeHTTP(
        response(
            {
                "loginUrl": "https://account.xiaomi.com/qr",
                "lp": "https://account.xiaomi.com/longPolling/lp",
                "timeout": 180,
            }
        ),
        *(requests.exceptions.Timeout("private") for _ in range(36)),
    )
    monkeypatch.setattr("mi_home_cli.auth.time.monotonic", lambda: 1)
    with pytest.raises(AuthenticationError, match="expired"):
        Authenticator(http, store, UI()).qr("de")
    assert len(http.calls) == 37


def test_password_captcha_then_success(store):
    http = FakeHTTP(
        response({"_sign": "test-sign"}),
        response({"captchaUrl": "/captcha/image"}),
        response(text="fake-png"),
        response(completion()),
        response(cookies={"serviceToken": SERVICE}),
    )
    session = Authenticator(http, store, UI("account", "fake-password", "answer")).password("de")
    assert session.service_token == SERVICE
    submits = [c for c in http.calls if c[0] == "POST"]
    assert all("hash" in c[2]["data"] and "params" not in c[2] for c in submits)
    assert not (store.path / "captcha.png").exists()
    assert not (store.path / "session.json").exists()


def test_password_captcha_limit(store):
    responses = [response({"_sign": "test-sign"})]
    for _ in range(3):
        responses.extend([response({"captchaUrl": "/captcha/image"}), response(text="image")])
    http = FakeHTTP(*responses)
    with pytest.raises(AuthenticationError, match="retry limit"):
        Authenticator(http, store, UI("account", "fake-password", "a", "b", "c")).password("de")
    assert len([c for c in http.calls if c[0] == "POST"]) == 3


@pytest.mark.parametrize("data", [{"code": 70016}, {"code": 70022}, {"code": 20023}])
def test_rejection_not_automatically_retried(store, data):
    http = FakeHTTP(response({"_sign": "sign"}), response(data))
    with pytest.raises((AuthenticationError, RateLimitError)):
        Authenticator(http, store, UI("account", "wrong-password")).password("de")
    assert len(http.calls) == 2


@pytest.mark.parametrize(
    ("flag", "selection", "channel"), [(8, "email", "Email"), (4, "sms", "Phone")]
)
def test_full_2fa_redirect_chain(store, flag, selection, channel):
    http = FakeHTTP(
        response({"_sign": "sign"}),
        response(
            {"notificationUrl": "https://account.xiaomi.com/identity/authStart?context=private"}
        ),
        response(),
        response({"options": [8, 4]}),
        response({"code": 0}),
        response({"code": 0, "location": "https://account.xiaomi.com/identity/result/check"}),
        response(status=302, headers={"Location": "/pass/serviceLoginAuth2/end"}),
        response(
            status=302,
            headers={
                "extension-pragma": json.dumps({"ssecurity": SECURITY, "userId": "test-user"}),
                "Location": "https://sts.api.io.mi.com/sts",
            },
        ),
        response(cookies={"serviceToken": SERVICE}),
    )
    session = Authenticator(
        http, store, UI("account", "fake-password", selection, "123456")
    ).password("de")
    assert session.service_token == SERVICE
    verify = [c for c in http.calls if f"verify{channel}" in c[1]][0]
    assert verify[2]["data"]["_flag"] == str(flag)
    assert verify[2]["data"]["trust"] == "false"


def test_2fa_retries_bounded(store):
    http = FakeHTTP(
        response(),
        response({"options": [8]}),
        response({"code": 0}),
        *(response({"code": 70014}) for _ in range(3)),
    )
    with pytest.raises(AuthenticationError, match="retry limit"):
        Authenticator(http, store, UI("1", "2", "3"))._two_factor(
            "https://account.xiaomi.com/identity/authStart?context=private", "de"
        )
    assert len(http.calls) == 6


def test_unsupported_2fa_fails_safely(store):
    http = FakeHTTP(response(), response({"options": [16]}))
    with pytest.raises(AuthenticationError, match="unsupported"):
        Authenticator(http, store, UI())._two_factor(
            "https://account.xiaomi.com/identity/authStart?context=private", "de"
        )


def test_no_service_token_is_not_success(store):
    http = FakeHTTP(response())
    with pytest.raises(AuthenticationError, match="service token"):
        Authenticator(http, store, UI())._finish(completion(), "de")
