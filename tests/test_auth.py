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
        response({"code": 70016, "_sign": "test-sign"}),
        response({"code": 70016, "captchaUrl": "/captcha/image"}),
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
        response({"code": 70016, "_sign": "sign"}),
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


def test_70016_bootstrap_challenge_is_not_a_failed_password(store):
    http = FakeHTTP(
        response({"code": 70016, "_sign": "test-sign", "captchaUrl": None}),
        response(completion()),
        response(cookies={"serviceToken": SERVICE}),
    )
    session = Authenticator(http, store, UI("account", "fake-password")).password("de")
    assert session.service_token == SERVICE
    assert [call[0] for call in http.calls] == ["GET", "POST", "GET"]


@pytest.mark.parametrize("code", [70022, 20023])
def test_bootstrap_rate_limit_is_not_ignored_even_with_sign(store, code):
    http = FakeHTTP(response({"code": code, "_sign": "test-sign"}))
    with pytest.raises(RateLimitError, match="preparing login"):
        Authenticator(http, store, UI("account", "fake-password")).password("de")
    assert len(http.calls) == 1


def test_bootstrap_missing_sign_reports_phase_without_blame_or_secrets(store):
    http = FakeHTTP(response({"code": 70016, "description": SERVICE}))
    with pytest.raises(AuthenticationError, match="preparing login") as caught:
        Authenticator(http, store, UI("account", "fake-password")).password("de")
    assert "rejected the account or password" not in str(caught.value)
    assert SERVICE not in str(caught.value)
    assert len(http.calls) == 1


@pytest.mark.parametrize("regional_redirect", [False, True])
def test_regional_email_verification_retains_origin_context_and_cookies(
    store, regional_redirect, caplog
):
    origin = "https://eu.account.xiaomi.com"
    notification = origin + "/identity/authStart?context=private"
    steps = [response({"code": 70016, "_sign": "test-sign"})]
    if regional_redirect:
        notification = "https://account.xiaomi.com/identity/authStart?context=private"
    steps.append(response({"notificationUrl": notification}))
    if regional_redirect:
        steps.append(
            response(
                status=302, headers={"Location": origin + "/identity/authStart?context=private"}
            )
        )
    steps.extend(
        [
            response(cookies={"ick": "first-test-cookie"}),
            response({"options": [8]}),
            response({"code": 0}, cookies={"ick": "next-test-cookie"}),
            response({"code": 0, "location": "/identity/result/check"}),
            response(status=302, headers={"Location": "/pass/serviceLoginAuth2/end"}),
            response(
                status=302,
                headers={
                    "extension-pragma": json.dumps({"ssecurity": SECURITY}),
                    "Location": "https://sts.api.io.mi.com/sts",
                },
                cookies={"userId": "test-user"},
            ),
            response(cookies={"serviceToken": SERVICE}),
        ]
    )
    http = FakeHTTP(*steps)
    ui = UI("account", "fake-password", "test-email-code")
    session = Authenticator(http, store, ui).password("de")
    assert session.user_id == "test-user"
    assert session.service_token == SERVICE
    send = next(call for call in http.calls if call[1].endswith("sendEmailTicket"))
    verify = next(call for call in http.calls if call[1].endswith("verifyEmail"))
    assert send[1].startswith(origin)
    assert verify[1].startswith(origin)
    assert send[2]["data"]["ick"] == "first-test-cookie"
    assert verify[2]["data"]["ick"] == "next-test-cookie"
    assert verify[2]["data"]["ticket"] == "test-email-code"
    assert send[2]["params"]["mask"] == verify[2]["params"]["mask"] == "0"
    assert verify[2]["params"]["_flag"] == "8"
    assert verify[2]["params"]["context"] == "private"
    assert all(call[2]["verify"] is True for call in http.calls)
    assert "test-email-code" not in str(ui.messages) + caplog.text
    assert SERVICE not in str(ui.messages) + caplog.text


@pytest.mark.parametrize("host", ["eu.lp.account.xiaomi.com", "sts.api.io.mi.com"])
def test_non_identity_host_cannot_start_verification(store, host):
    http = FakeHTTP()
    with pytest.raises(ProtocolError):
        Authenticator(http, store, UI())._two_factor(
            f"https://{host}/identity/authStart?context=private", "de"
        )
    assert not http.calls


def test_csrf_cookie_respects_host_and_path(store):
    http = FakeHTTP()
    http.session.cookies.set(
        "ick", "regional-cookie", domain="eu.account.xiaomi.com", path="/identity"
    )
    http.session.cookies.set("ick", "global-cookie", domain="account.xiaomi.com", path="/identity")
    auth = Authenticator(http, store, UI())
    assert (
        auth._cookie_for("ick", "https://eu.account.xiaomi.com/identity/auth/verifyEmail")
        == "regional-cookie"
    )
    assert (
        auth._cookie_for("ick", "https://account.xiaomi.com/identity/auth/verifyEmail")
        == "global-cookie"
    )
    assert auth._cookie_for("ick", "https://eu.account.xiaomi.com/pass/serviceLogin") == ""
