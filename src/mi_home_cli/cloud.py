"""Read-only cloud API and deliberate allowlist of displayable device fields."""

import base64
import json
from dataclasses import dataclass, field

from .auth import Session
from .errors import AuthenticationError, ProtocolError, RateLimitError, RegionError
from .protocol import encrypted_params, generate_nonce, rc4, signed_nonce
from .transport import REGIONS, Transport, parse_json


def regions_for(selection: str) -> tuple[str, ...]:
    if selection == "all":
        return REGIONS
    if selection not in REGIONS:
        raise RegionError("Unknown Xiaomi region. Choose cn,de,us,ru,tw,sg,in,i2 or all.")
    return (selection,)


def clean(value):
    if value is None or not isinstance(value, (str, int, float, bool)):
        return None
    # Prevent terminal control sequences/newlines from cloud-provided names.
    return "".join(c for c in str(value) if c.isprintable())[:256]


@dataclass
class Device:
    did: str | None
    name: str | None
    model: str | None
    ip: str | None
    mac: str | None
    region: str
    online: bool | None
    firmware: str | None
    token: str | None = field(repr=False)

    @classmethod
    def from_cloud(cls, data: dict, region: str):
        extra = data.get("extra")
        extra = extra if isinstance(extra, dict) else {}
        token = data.get("token")
        # miIO local tokens are exactly 16 bytes encoded in hexadecimal.
        if (
            not isinstance(token, str)
            or len(token) != 32
            or any(c not in "0123456789abcdefABCDEF" for c in token)
            or set(token) == {"0"}
        ):
            token = None
        return cls(
            clean(data.get("did")),
            clean(data.get("name")),
            clean(data.get("model")),
            clean(data.get("localip") or data.get("ip")),
            clean(data.get("mac")),
            region,
            data.get("isOnline") if isinstance(data.get("isOnline"), bool) else None,
            clean(extra.get("fw_version")),
            token,
        )

    def public(self, *, reveal=False) -> dict:
        return {
            "did": self.did,
            "name": self.name,
            "model": self.model,
            "ip": self.ip,
            "mac": self.mac,
            "region": self.region,
            "online": self.online,
            "firmware": self.firmware,
            "token": self.token if reveal else None,
            "token_available": self.token is not None,
        }


class Cloud:
    def __init__(self, transport: Transport, session: Session):
        self.http, self.session = transport, session

    def call(self, region: str, path: str, data: dict) -> dict:
        regions_for(region)
        # There is no public arbitrary API command and no device mutation endpoint.
        if path not in ("/home/device_list", "/v2/homeroom/gethome", "/v2/home/home_device_list"):
            raise ProtocolError("Only read-only device discovery endpoints are supported.")
        url = "https://" + ("" if region == "cn" else region + ".") + "api.io.mi.com/app" + path
        nonce = generate_nonce()
        try:
            fields = encrypted_params(
                url,
                self.session.ssecurity,
                nonce,
                {
                    "data": json.dumps(data, separators=(",", ":")),
                },
            )
        except (ValueError, TypeError):
            raise AuthenticationError("Saved session is invalid. Log in again.") from None
        response = self.http.request(
            "POST",
            url,
            data=fields,
            cookies={
                "userId": self.session.user_id,
                "serviceToken": self.session.service_token,
                "yetAnotherServiceToken": self.session.service_token,
                "locale": "en_GB",
            },
            headers={
                "Accept-Encoding": "identity",
                "MIOT-ENCRYPT-ALGORITHM": "ENCRYPT-RC4",
                "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
            },
        )
        try:
            if response.text.startswith(("{", "&&&START&&&")):
                result = parse_json(response.text)
            else:
                decoded = rc4(
                    signed_nonce(self.session.ssecurity, nonce),
                    base64.b64decode(response.text, validate=True),
                )
                result = parse_json(decoded.decode())
        except (ValueError, UnicodeError):
            raise ProtocolError(
                "Could not decode Xiaomi response; the session may have expired."
            ) from None
        code = result.get("code")
        if code in (401, -10001, -10002):
            raise AuthenticationError("Xiaomi session expired. Run 'mi-home-cli login' again.")
        if code in (429, -7, -704042011):
            raise RateLimitError("Xiaomi cloud rate limit reached. Wait before retrying.")
        if code != 0:
            raise RegionError(
                "Xiaomi rejected device discovery in this region. Check region or retry later."
            )
        result = result.get("result")
        if not isinstance(result, dict):
            raise ProtocolError("Xiaomi device response has no result object.")
        return result

    def devices(self, region: str) -> list[Device]:
        # Legacy endpoint used by both desktop tools; v2 adds home/shared devices.
        result = self.call(
            region, "/home/device_list", {"getVirtualModel": False, "getHuamiDevices": 0}
        )
        rows = self._rows(result, "list")
        homes = self.call(
            region,
            "/v2/homeroom/gethome",
            {
                "fg": True,
                "fetch_share": True,
                "fetch_share_dev": True,
                "limit": 300,
                "app_ver": 7,
            },
        )
        home_rows = self._rows(homes, "homelist") + self._rows(homes, "share_home_list")
        if homes.get("has_more") or len(home_rows) >= 300:
            raise ProtocolError(
                "Xiaomi returned a truncated home list; this account exceeds MVP limits."
            )
        for home in home_rows:
            if home.get("id") is None or home.get("uid") is None:
                raise ProtocolError(
                    "Xiaomi home has no ID or owner; cannot safely complete discovery."
                )
            devices = self.call(
                region,
                "/v2/home/home_device_list",
                {
                    "home_owner": home["uid"],
                    "home_id": home["id"],
                    "limit": 200,
                    "get_split_device": True,
                    "support_smart_home": True,
                },
            )
            home_devices = self._rows(devices, "device_info")
            if devices.get("has_more") or len(home_devices) >= 200:
                raise ProtocolError(
                    "Xiaomi returned a truncated device list; this home exceeds MVP limits."
                )
            rows.extend(home_devices)
        unique = {}
        for index, row in enumerate(rows):
            device = Device.from_cloud(row, region)
            key = device.did or f"missing-{index}"
            old = unique.get(key)
            if old is None:
                unique[key] = device
            else:
                # Do not let a sparse shared-device record erase an available local token/IP.
                for attribute in ("name", "model", "ip", "mac", "online", "firmware", "token"):
                    if getattr(device, attribute) is not None:
                        setattr(old, attribute, getattr(device, attribute))
        return list(unique.values())

    @staticmethod
    def _rows(result: dict, key: str) -> list[dict]:
        rows = result.get(key, [])
        if rows is None:
            return []
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ProtocolError("Xiaomi returned an invalid device or home list.")
        return rows
