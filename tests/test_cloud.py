import base64
import json

import pytest

from mi_home_cli.cloud import Cloud, Device, regions_for
from mi_home_cli.errors import AuthenticationError, ProtocolError, RateLimitError, RegionError
from mi_home_cli.protocol import encrypted_params, rc4, signed_nonce

from .conftest import SECURITY, TOKEN, FakeHTTP, response


def test_upstream_known_nonce_vector():
    # Public protocol vector in mi-home-toolkit, not real credentials.
    assert (
        signed_nonce("9wR21gAtfAyn+KDX1ok/Iw==", "BejIOTLgvecBs9sT")
        == "zq3TaSr/VwnmvvWwMTAEMAuzxs2gLgP6uFJS7bBtWKo="  # pragma: allowlist secret - public deterministic test fixture, not credentials
    )


def test_encrypted_cloud_response_and_post_body(session, monkeypatch):
    nonce = base64.b64encode(bytes(range(12))).decode()
    monkeypatch.setattr("mi_home_cli.cloud.generate_nonce", lambda: nonce)
    body = {"code": 0, "result": {"list": []}}
    encoded = base64.b64encode(
        rc4(signed_nonce(SECURITY, nonce), json.dumps(body).encode())
    ).decode()
    http = FakeHTTP(response(text=encoded))
    assert Cloud(http, session).call("de", "/home/device_list", {}) == {"list": []}
    sent = http.calls[0][2]
    assert "params" not in sent
    assert sent["data"]["_nonce"] == nonce
    assert "MIOT-ENCRYPT-ALGORITHM" in sent["headers"]


def test_crypto_matches_vendored_request_contract():
    # Golden output obtained by running the unmodified upstream MIT class at the pinned revision.
    nonce = base64.b64encode(bytes(range(12))).decode()
    params = encrypted_params(
        "https://de.api.io.mi.com/app/home/device_list",
        SECURITY,
        nonce,
        {"data": '{"getVirtualModel":false,"getHuamiDevices":0}'},
    )
    assert (
        base64.b64decode(params["data"]).hex()
        == "1a373ededde7462a8d54f5d39f7187039b7a6be23681298e3ecb501820c864097f77a8eefaa4dcd370781b8186"  # pragma: allowlist secret - public deterministic test fixture, not credentials
    )
    assert params["signature"] == "IOlgIuruwk9Fq6TAmJM66oqIhwE="
    public_hash = "NGws1YKBTmi4R9nWtE/IDcYuafA2iAmIJ5BuQA=="  # pragma: allowlist secret
    assert params["rc4_hash__"] == public_hash


def test_v2_devices_merge_and_preserve_legacy_token(session, device):
    http = FakeHTTP(
        response({"code": 0, "result": {"list": [device]}}),
        response({"code": 0, "result": {"homelist": [{"id": 1, "uid": 2}]}}),
        response(
            {
                "code": 0,
                "result": {"device_info": [{"did": "123", "name": "Heater"}, {"did": "456"}]},
            }
        ),
    )
    devices = Cloud(http, session).devices("de")
    assert len(devices) == 2
    assert devices[0].token == TOKEN
    assert devices[0].name == "Heater"
    assert devices[1].ip is None
    assert all("de.api.io.mi.com" in c[1] for c in http.calls)


@pytest.mark.parametrize("region", ["de", "cn", "tw", "i2"])
def test_region_host(session, region):
    http = FakeHTTP(response({"code": 0, "result": {}}))
    Cloud(http, session).call(region, "/home/device_list", {})
    assert http.calls[0][1].startswith(
        "https://" + ("" if region == "cn" else region + ".") + "api.io.mi.com/"
    )


def test_regions():
    assert len(regions_for("all")) == 8
    assert regions_for("de") == ("de",)
    with pytest.raises(RegionError):
        regions_for("invalid")


@pytest.mark.parametrize(
    ("code", "error"),
    [
        (401, AuthenticationError),
        (-10001, AuthenticationError),
        (429, RateLimitError),
        (-7, RateLimitError),
        (-1, RegionError),
    ],
)
def test_cloud_error_codes_safe(session, code, error):
    http = FakeHTTP(response({"code": code, "message": TOKEN}))
    with pytest.raises(error) as caught:
        Cloud(http, session).call("de", "/home/device_list", {})
    assert TOKEN not in str(caught.value)


@pytest.mark.parametrize("token", [None, "", "0" * 32, "F" * 31, "g" * 32, ["invalid"]])
def test_missing_invalid_tokens(token):
    device = Device.from_cloud({"token": token}, "de")
    assert device.token is None
    assert not device.public()["token_available"]


def test_field_allowlist_and_terminal_escape_safety(device):
    item = Device.from_cloud(device | {"name": "heater\n\x1b[31m"}, "de")
    assert "\x1b" not in item.name and "\n" not in item.name
    assert TOKEN not in repr(item)
    assert TOKEN not in json.dumps(item.public())
    assert "never-export-this" not in json.dumps(item.public(reveal=True))
    assert item.public(reveal=True)["token"] == TOKEN


def test_mutation_endpoint_forbidden(session):
    with pytest.raises(ProtocolError):
        Cloud(FakeHTTP(), session).call("de", "/miotspec/prop/set", {})


def test_large_home_is_not_silently_truncated(session):
    http = FakeHTTP(
        response({"code": 0, "result": {"list": []}}),
        response({"code": 0, "result": {"homelist": [], "has_more": True}}),
    )
    with pytest.raises(ProtocolError, match="truncated"):
        Cloud(http, session).devices("de")


def test_unsupported_legacy_endpoint_falls_back_to_v2(session, device):
    http = FakeHTTP(
        response({"code": -1, "message": "unsupported legacy endpoint"}),
        response({"code": 0, "result": {"homelist": [{"id": 1, "uid": 2}]}}),
        response({"code": 0, "result": {"device_info": [device]}}),
    )
    assert Cloud(http, session).devices("de")[0].token == TOKEN


def test_empty_null_lists_are_supported(session):
    http = FakeHTTP(
        response({"code": 0, "result": {"list": None}}),
        response({"code": 0, "result": {"homelist": None}}),
    )
    assert Cloud(http, session).devices("de") == []
