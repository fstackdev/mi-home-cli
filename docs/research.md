# Research and licensing

Inspected on 2026-11-08. Repository revisions are pinned here for reproducibility.

| Source | Findings and decision |
| --- | --- |
| [Homey token instructions](https://github.com/shaarkys/com.xiaomi-miio/blob/master/docs/obtain_token.md) | Method 1 names `home/device_list` and the two desktop tools. Cloud extraction avoids resetting the heater or installing an obsolete Android app. Documentation only; no code copied. |
| [Xiaomi-cloud-tokens-extractor](https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor/tree/c4db715dace9806e905153c2977608873e8ab7c9) | MIT. Selected source for vendored RC4/signature/nonce functions and adapted QR/password/email 2FA flow. Keeps a tiny runtime rather than importing a script with argparse side effects, Pillow, a webserver and unredacted debug/output. Copyright/license included in distribution. |
| [Get_MiHome_devices_token](https://github.com/Maxmudjon/Get_MiHome_devices_token/tree/fee89832e61dd58443823713b15aad28db792d11) | Electron UI, `node-mihome` 0.0.30 and `miio`. Its manifest declares ISC, but no standalone license was found. Inspected for regional listing behavior; no code copied or dependency added. |
| [mi-home-toolkit](https://github.com/ApplY3D/mi-home-toolkit/tree/ce9c93706d8b3591649c8028ae3e37593ac7d6dc) | Tauri/Angular/Rust client uses `/home/device_list`, password CAPTCHA and identity verification. Identity options 4/8 indicate phone/email. No root LICENSE found in inspected revision, so no code copied. Protocol behavior cross-checked against MIT extractor. |
| [mihome-ctl 0.3.0](https://pypi.org/project/mihome-ctl/0.3.0/) | MIT project already vendors a trimmed extractor and adds terminal QR/session caching. Useful precedent, but depends on Pillow, tyro, platformdirs, colorama and more; exposes IR control and persists raw device tokens. Its public dependency surface is larger than this read-only MVP. No code copied. Current repository also inspected at `10deea0cf5aa147f7e28d2b4de2428c094ffdbaf` (0.7.0), distinguished from the requested PyPI version. |

## Wire protocol and endpoints

QR login calls `account.xiaomi.com/longPolling/loginUrl`, encodes `loginUrl` in a
terminal QR, polls `lp`, captures `userId` / `ssecurity`, then visits the validated
STS `location` to obtain `serviceToken`. No browser or local HTTP server is needed.

Password login obtains `_sign` at `/pass/serviceLogin` and submits an MD5-derived
challenge at `/pass/serviceLoginAuth2`. CAPTCHA images and `notificationUrl` trigger
bounded interactive challenges. Email/SMS use identity list, send ticket and verify
endpoints; redirect headers supply `ssecurity` and STS cookies. Unrecognized variants
fail safely with QR guidance; no claim of supporting every Xiaomi verification scheme.

Discovery POSTs use Xiaomi's RC4-drop-1024 payload scheme and SHA-1 signature over
method/path/fields/signed nonce. The signed nonce is SHA-256(ssecurity || nonce).
Each POST is a form body, including auth fields, rather than a secret-bearing query
string. Requests use verified HTTPS and validate every redirect before following it.

Regions: `cn` uses `api.io.mi.com`; others use `{region}.api.io.mi.com`, under `/app`.
The CLI reads `/home/device_list` then `/v2/homeroom/gethome` and
`/v2/home/home_device_list` to include home-based devices. Records merge by DID within
a region, preserving nonempty fields. Cross-region records remain distinguishable.

## Dependencies

Runtime direct dependencies: requests (Apache-2.0), PyCryptodome (BSD/public-domain
components), qrcode (BSD). Transitives include certifi (MPL-2.0), charset-normalizer
(MIT), idna (BSD-3-Clause) and urllib3 (MIT). They are used unmodified. Their licenses
remain in installed wheel metadata. No GPL/AGPL source is copied or vendored. Standard
Python supplies argparse, JSON, secure file permissions and POSIX advisory locking.

Vendoring only the small MIT protocol/auth portion is intentional: the upstream is an
executable script rather than an import-safe minimal library. No existing general
Xiaomi SDK with the same small read-only, bounded and secret-safe interface was found
among the requested sources. Upstream cryptographic operations are reused, with new
transport, state, UI and error boundaries rather than redesigning the wire protocol.
