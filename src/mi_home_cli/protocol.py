"""MIT-derived Xiaomi RC4 protocol from PiotrMachowski's token_extractor.py.

Upstream c4db715dace9806e905153c2977608873e8ab7c9. See THIRD_PARTY_LICENSES.
RC4 and SHA-1 are Xiaomi wire requirements; TLS still verifies certificates.
"""

import base64
import hashlib
import os
import time
from urllib.parse import urlsplit

# Maintained PyCryptodome, not PyCrypto. ARC4 is required by the Xiaomi wire protocol.
from Crypto.Cipher import ARC4  # nosec B413


def generate_nonce() -> str:
    return base64.b64encode(os.urandom(8) + int(time.time() / 60).to_bytes(4, "big")).decode()


def signed_nonce(ssecurity: str, nonce: str) -> str:
    return base64.b64encode(
        hashlib.sha256(base64.b64decode(ssecurity) + base64.b64decode(nonce)).digest()
    ).decode()


def signature(url: str, key: str, params: dict) -> str:
    path = urlsplit(url).path.removeprefix("/app")
    parts = ["POST", path, *(f"{k}={v}" for k, v in params.items()), key]
    return base64.b64encode(
        hashlib.sha1("&".join(parts).encode(), usedforsecurity=False).digest()
    ).decode()


def rc4(key: str, data: bytes) -> bytes:
    # Xiaomi mandates RC4-drop-1024; all traffic additionally uses verified TLS.
    cipher = ARC4.new(base64.b64decode(key))  # nosec B304
    cipher.encrypt(bytes(1024))
    return cipher.encrypt(data)


def encrypted_params(url: str, security: str, nonce: str, params: dict) -> dict:
    key = signed_nonce(security, nonce)
    data = dict(params)
    data["rc4_hash__"] = signature(url, key, data)
    data = {k: base64.b64encode(rc4(key, v.encode())).decode() for k, v in data.items()}
    data["signature"] = signature(url, key, data)
    data.update(ssecurity=security, _nonce=nonce)
    return data
