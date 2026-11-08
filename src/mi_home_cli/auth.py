"""Bounded QR/password authentication adapted from the MIT token extractor.

See THIRD_PARTY_LICENSES and docs/research.md. No password or cookie persistence.
"""

import hashlib
import secrets
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, urljoin, urlsplit

import requests

from .errors import AuthenticationError, MiHomeError, NetworkError, ProtocolError, RateLimitError
from .storage import Store, write_private
from .transport import ACCOUNT_HOSTS, AUTH_HOST, Transport, parse_json, trusted_url


@dataclass(repr=False)
class Session:
    user_id: str
    ssecurity: str
    service_token: str
    region: str = "de"

    def to_dict(self):
        return {k: getattr(self, k) for k in ("user_id", "ssecurity", "service_token", "region")}


def check_code(data: dict, *, allow_challenge: bool = False):
    if data.get("code") == 70016 and not allow_challenge:
        raise AuthenticationError(
            "Xiaomi rejected the account or password. Check it before retrying."
        )
    if data.get("code") in (70022, 20023):
        raise RateLimitError(
            "Xiaomi rejected or limited the login. Check credentials and wait before retrying."
        )


class Authenticator:
    def __init__(self, transport: Transport, store: Store, ui):
        self.http = transport
        self.store = store
        self.ui = ui

    def _captcha(self, path: str) -> str:
        image_url = trusted_url(urljoin(AUTH_HOST, path))
        response = self.http.request("GET", image_url)
        self.store.prepare()
        image = self.store.path / "captcha.png"
        # Image stays in the private directory; no HTTP server, GUI or external image service.
        write_private(image, response.content, replace=True)
        try:
            self.ui.message(f"CAPTCHA required. Open the private image on your computer: {image}")
            self.ui.message(
                "Over SSH, copy that file with scp. Enter the letters below; nothing is echoed."
            )
            return self.ui.secret("CAPTCHA: ")
        finally:
            image.unlink(missing_ok=True)

    def _finish(self, data: dict, region: str) -> Session:
        check_code(data)
        if not data.get("ssecurity") or not data.get("userId") or not data.get("location"):
            raise AuthenticationError(
                "Xiaomi did not complete authentication. Try QR login or retry later."
            )
        response = self.http.request("GET", trusted_url(data["location"]))
        # Redirect cookies may have been set at intermediate hops.
        tokens = [
            c.value
            for c in self.http.session.cookies
            if c.name == "serviceToken"
            and (c.domain == "sts.api.io.mi.com" or c.domain.endswith(".api.io.mi.com"))
        ]
        token = response.cookies.get("serviceToken") or (tokens[-1] if tokens else None)
        if not token:
            raise AuthenticationError("Xiaomi did not issue a service token. Try QR login again.")
        return Session(str(data["userId"]), str(data["ssecurity"]), str(token), region)

    def qr(self, region: str) -> Session:
        data = self.http.json(
            "GET",
            AUTH_HOST + "/longPolling/loginUrl",
            params={
                "_qrsize": "480",
                "qs": "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
                "callback": "https://sts.api.io.mi.com/sts",
                "_hasLogo": "false",
                "sid": "xiaomiio",
                "serviceParam": "",
                "_locale": "en_GB",
                "_dc": str(int(time.time() * 1000)),
            },
        )
        check_code(data)
        if not all(data.get(k) for k in ("loginUrl", "lp", "timeout")):
            raise AuthenticationError(
                "Xiaomi QR login is unavailable. Try 'login --method password'."
            )
        login_url = trusted_url(data["loginUrl"])
        poll_url = trusted_url(data["lp"])
        self.ui.qr(login_url)
        try:
            lifetime = min(max(float(data["timeout"]), 1), 180)
        except (ValueError, TypeError):
            raise ProtocolError("Xiaomi returned an invalid QR expiration time.") from None
        deadline = time.monotonic() + lifetime
        for _ in range(36):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                response = self.http.request("GET", poll_url, timeout=min(10, remaining))
            except NetworkError as error:
                if "timed out" not in str(error):
                    raise
                continue
            result = parse_json(response.text)
            check_code(result)
            if result.get("ssecurity"):
                return self._finish(result, region)
            if result.get("code") not in (None, 0):
                raise AuthenticationError("QR was rejected or expired. Run login again when ready.")
            # A pending HTTP-200 response must not cause a tight poll loop.
            time.sleep(min(1, max(0, deadline - time.monotonic())))
        raise AuthenticationError(
            "QR login expired. Run login again and approve it in Xiaomi Home."
        )

    def password(self, region: str) -> Session:
        username = self.ui.text("Xiaomi account (email, phone or ID): ")
        password = self.ui.secret("Xiaomi password: ")
        if not username or not password:
            raise AuthenticationError("Account and password are required.")
        device_id = secrets.token_hex(6)
        for domain in (".mi.com", ".xiaomi.com"):
            self.http.session.cookies.set("deviceId", device_id, domain=domain)
            self.http.session.cookies.set("sdkVersion", "accountsdk-18.8.15", domain=domain)
        # Wire requirement, not a stored password hash. Send only in HTTPS form bodies.
        password_hash = hashlib.md5(password.encode(), usedforsecurity=False).hexdigest().upper()
        del password
        phase = "preparing login"
        try:
            sign = None
            captcha = None
            for _ in range(3):
                params = {"sid": "xiaomiio", "_json": "true"}
                if captcha:
                    params["captCode"] = captcha
                first = self.http.json(
                    "GET",
                    AUTH_HOST + "/pass/serviceLogin",
                    params=params,
                    cookies={"userId": username},
                )
                # An unauthenticated serviceLogin normally returns 70016 WITH _sign.
                # No password has been submitted at this stage; continue the challenge.
                check_code(first, allow_challenge=True)
                if first.get("captchaUrl"):
                    captcha = self._captcha(first["captchaUrl"])
                    continue
                sign = first.get("_sign")
                break
            if not sign:
                raise AuthenticationError(
                    "Could not start password login. Use QR login or retry later."
                )
            fields = {
                "sid": "xiaomiio",
                "hash": password_hash,
                "callback": "https://sts.api.io.mi.com/sts",
                "qs": "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
                "user": username,
                "_sign": sign,
                "_json": "true",
            }
            for _ in range(3):
                phase = "submitting credentials"
                result = self.http.json(
                    "POST", AUTH_HOST + "/pass/serviceLoginAuth2", data=fields, follow=False
                )
                # Honor rate limits immediately, but inspect advertised challenges first.
                check_code(result, allow_challenge=True)
                if result.get("captchaUrl"):
                    fields["captCode"] = self._captcha(result["captchaUrl"])
                    if result.get("_sign"):
                        fields["_sign"] = result["_sign"]
                    continue
                if result.get("notificationUrl"):
                    phase = "identity verification"
                    return self._two_factor(result["notificationUrl"], region)
                check_code(result)
                phase = "exchanging cloud session"
                return self._finish(result, region)
            raise AuthenticationError(
                "CAPTCHA retry limit reached. Check password and retry later."
            )
        except MiHomeError as error:
            raise type(error)(f"Password login ({phase}): {error}") from None
        finally:
            # Only minimal cloud credentials are ever written by Store.save().
            del password_hash

    def _cookie_for(self, name: str, url: str) -> str:
        # Apply Requests' domain/path/expiry/secure rules to each candidate. A regional
        # cookie takes precedence over a same-name parent-domain cookie for CSRF data.
        prepared = requests.Request("GET", trusted_url(url)).prepare()
        candidates = []
        for cookie in self.http.session.cookies:
            if cookie.name != name:
                continue
            jar = requests.cookies.RequestsCookieJar()
            jar.set_cookie(cookie)
            if requests.cookies.get_cookie_header(jar, prepared):
                candidates.append(cookie)
        if not candidates:
            return ""
        selected = max(candidates, key=lambda cookie: (len(cookie.domain), len(cookie.path)))
        return selected.value or ""

    def _two_factor(self, notification: str, region: str) -> Session:
        notification = trusted_url(urljoin(AUTH_HOST, notification))
        if urlsplit(notification).hostname not in ACCOUNT_HOSTS:
            raise ProtocolError("Unsupported Xiaomi identity verification host.")
        self.ui.message("Xiaomi requires additional verification; preparing email/SMS options.")
        start = self.http.request("GET", notification)
        destination = urlsplit(trusted_url(start.url or notification))
        if destination.hostname not in ACCOUNT_HOSTS:
            raise ProtocolError("Unsupported Xiaomi identity verification host.")
        identity_host = f"https://{destination.hostname}"
        context = (
            parse_qs(destination.query).get("context", [None])[0]
            or parse_qs(urlsplit(notification).query).get("context", [None])[0]
        )
        if not context:
            raise AuthenticationError("Unsupported Xiaomi verification challenge. Use QR login.")
        common = {"sid": "xiaomiio", "context": context, "_locale": "en_US"}
        choices = self.http.json("GET", identity_host + "/identity/list", params=common)
        offered = choices.get("options", [])
        if not isinstance(offered, list):
            offered = []
        offered = [flag for flag in (8, 4) if flag in offered]
        if not offered:
            raise AuthenticationError(
                "Xiaomi requires unsupported account verification. Use QR login or verify in the Xiaomi app."
            )
        flag = offered[0]
        if len(offered) > 1:
            choice = self.ui.text("Verification method [email/sms] (email): ").lower()
            if choice not in ("", "email", "sms"):
                raise AuthenticationError("Choose email or sms and run login again.")
            flag = 4 if choice == "sms" else 8
        channel = "Phone" if flag == 4 else "Email"
        send_url = identity_host + f"/identity/auth/send{channel}Ticket"
        response = self.http.json(
            "POST",
            send_url,
            params=common | {"mask": "0", "_dc": str(int(time.time() * 1000))},
            data={
                "retry": "0",
                "icode": "",
                "_json": "true",
                "ick": self._cookie_for("ick", send_url),
            },
        )
        check_code(response)
        if response.get("code") != 0:
            raise AuthenticationError(
                "Xiaomi could not send a verification code. Use QR login or retry later."
            )
        self.ui.message("Xiaomi sent a verification code by " + ("SMS." if flag == 4 else "email."))
        for _ in range(3):
            code = self.ui.secret("2FA code: ")
            verify_url = identity_host + f"/identity/auth/verify{channel}"
            verified_response = self.http.request(
                "POST",
                verify_url,
                follow=False,
                params=common | {"mask": "0", "_flag": str(flag), "_json": "true"},
                data={
                    "_flag": str(flag),
                    "ticket": code,
                    "trust": "false",
                    "_json": "true",
                    "ick": self._cookie_for("ick", verify_url),
                },
            )
            try:
                verified = parse_json(verified_response.text)
            except ProtocolError:
                if not verified_response.headers.get("Location"):
                    raise AuthenticationError(
                        "Unexpected Xiaomi verification response. Use QR login."
                    ) from None
                verified = {"code": 0}
            check_code(verified)
            if verified.get("code") == 70014:
                self.ui.message("Incorrect verification code.")
                continue
            if verified.get("code") != 0:
                raise AuthenticationError(
                    "Xiaomi rejected verification. Use QR login or retry later."
                )
            location = verified.get("location") or verified_response.headers.get("Location")
            base_url = verified_response.url or verify_url
            if not location:
                response = self.http.request(
                    "GET", identity_host + "/identity/result/check", params=common, follow=False
                )
                location = response.headers.get("Location")
                base_url = response.url or identity_host
            security = None
            user_id = None
            # Inspect every redirect to retain extension-pragma with ssecurity.
            for _ in range(8):
                if not location:
                    break
                location = trusted_url(urljoin(base_url, location))
                response = self.http.request("GET", location, follow=False)
                base_url = response.url or location
                extension = response.headers.get("extension-pragma")
                if extension:
                    extra = parse_json(extension)
                    security = extra.get("ssecurity") or security
                    user_id = extra.get("userId") or user_id
                if security and urlsplit(location).hostname == "sts.api.io.mi.com":
                    # It has already been fetched; finish from cookies without a second STS request.
                    tokens = [
                        c.value for c in self.http.session.cookies if c.name == "serviceToken"
                    ]
                    ids = [c.value for c in self.http.session.cookies if c.name == "userId"]
                    if tokens and (user_id or ids):
                        return Session(str(user_id or ids[-1]), str(security), tokens[-1], region)
                location = response.headers.get("Location")
                if not location and "Xiaomi Account - Tips" in response.text:
                    location = response.url
            raise AuthenticationError(
                "Xiaomi verification did not issue a cloud session. Use QR login."
            )
        raise AuthenticationError("2FA retry limit reached. Wait before logging in again.")
