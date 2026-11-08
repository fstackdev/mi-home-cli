"""TLS-only transport, fixed errors, bounded requests and validated redirect hops."""

import json
import logging
from urllib.parse import urljoin, urlsplit

import requests

from .errors import AuthenticationError, NetworkError, ProtocolError, RateLimitError

REGIONS = ("cn", "de", "us", "ru", "tw", "sg", "in", "i2")
AUTH_HOST = "https://account.xiaomi.com"
ACCOUNT_HOSTS = {
    "account.xiaomi.com",
    "eu.account.xiaomi.com",
}
# Regional destinations returned by Xiaomi's verified-HTTPS QR bootstrap.
# Keep exact hosts rather than trusting arbitrary *.xiaomi.com destinations.
HOSTS = (
    ACCOUNT_HOSTS
    | {
        "eu.lp.account.xiaomi.com",
        "sts.api.io.mi.com",
        "api.io.mi.com",
    }
    | {f"{region}.api.io.mi.com" for region in REGIONS if region != "cn"}
)


def trusted_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
        valid = (
            parsed.scheme == "https"
            and parsed.hostname in HOSTS
            and parsed.port in (None, 443)
            and not parsed.username
            and not parsed.password
            and not parsed.fragment
        )
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise ProtocolError("Xiaomi returned an unsupported redirect or verification host.")
    return url


def parse_json(text: str) -> dict:
    try:
        result = json.loads(text.removeprefix("&&&START&&&"))
        if not isinstance(result, dict):
            raise ValueError
        return result
    except (ValueError, TypeError):
        raise ProtocolError(
            "Xiaomi returned an unexpected response. Try QR login again later."
        ) from None


class Transport:
    def __init__(self):
        # urllib3 DEBUG logs include URLs (which can contain login tickets).
        for name in ("urllib3.connectionpool", "requests.packages.urllib3.connectionpool"):
            logging.getLogger(name).disabled = True
        self.session = requests.Session()
        # Ignore .netrc, environment proxies and TLS overrides; explicit verification below.
        self.session.trust_env = False
        self.session.headers["User-Agent"] = (
            "Android-7.1.1-1.0.0-ONEPLUS A3010-136-APP/com.xiaomi.mihome APPV/10.5.201"
        )

    def request(self, method: str, url: str, *, follow: bool = True, timeout=30, **kwargs):
        trusted_url(url)
        for _ in range(8):
            try:
                response = self.session.request(
                    method, url, allow_redirects=False, timeout=(10, timeout), verify=True, **kwargs
                )
            except requests.exceptions.Timeout:
                raise NetworkError("Xiaomi request timed out; no login was retried.") from None
            except requests.exceptions.RequestException:
                raise NetworkError(
                    "Cannot reach Xiaomi over verified TLS. Check DNS/network access."
                ) from None
            if response.status_code == 429:
                raise RateLimitError("Xiaomi rate limit reached. Wait before trying again.")
            if response.status_code in (401, 403):
                raise AuthenticationError(
                    "Xiaomi rejected this session. Run 'mi-home-cli login' again."
                )
            if response.status_code >= 400:
                raise NetworkError("Xiaomi service is unavailable. Try again later.")
            if not follow or response.status_code not in (301, 302, 303, 307, 308):
                return response
            location = response.headers.get("Location")
            if not location:
                raise ProtocolError("Xiaomi returned a redirect without a destination.")
            next_url = trusted_url(urljoin(url, location))
            # Never forward request bodies or explicitly supplied API cookies across redirects.
            if method != "GET":
                raise ProtocolError(
                    "Unexpected redirect during a Xiaomi submission; no retry sent."
                )
            kwargs = {}
            url = next_url
        raise ProtocolError("Xiaomi returned too many redirects.")

    def json(self, method: str, url: str, **kwargs) -> dict:
        return parse_json(self.request(method, url, **kwargs).text)

    def close(self):
        self.session.close()
