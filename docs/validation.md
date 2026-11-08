# Validation

## 0.1.2: Password bootstrap and regional identity verification

Reproduced the reported password error on Pi4 without any account credentials:
`/pass/serviceLogin` returns `code=70016` together with a nonempty `_sign`. This is a
normal unauthenticated bootstrap challenge, but versions 0.1.0/0.1.1 treated it as an
incorrect password and stopped before submitting credentials. 0.1.2 accepts that
challenge only while inspecting bootstrap/CAPTCHA/verification responses. A real
credential rejection after submission and all rate limits remain terminal.

Identity verification now accepts the existing exact global/European account hosts,
follows the final identity origin for list/send/verify requests, resolves relative
finish redirects against the preceding hop, and includes the upstream `mask`, flag
and scoped `ick` CSRF fields. Cookie selection delegates host/path/expiry rules to
Requests and prefers regional cookies over same-name parent-domain cookies. Errors
identify the login phase without dumping responses or credentials.

110 offline tests pass locally (90% statement coverage), including realistic 70016
bootstrap fixtures, actual post-submission rejection, rate limits, global-to-European
identity redirects, email/SMS flows, rotating CSRF cookies and cookie scope. Ruff and
Bandit pass. Live credential submission and receipt/verification of an email code are
still user-operated steps and have not been tested with the user's account.

## 0.1.1: European QR login host fix

The first real user attempt with 0.1.0 failed before showing a QR because the URL
allowlist omitted Xiaomi's European account and polling hosts. A credential-free
bootstrap request from Pi4 over verified HTTPS confirmed `eu.account.xiaomi.com`
for `loginUrl` and `eu.lp.account.xiaomi.com` for `lp`. Only hostname/scheme and
structural booleans were collected; QR tickets, full URLs and cookies were not logged.

0.1.1 permits these two exact destinations. Arbitrary subdomains, lookalike domains,
HTTP, URL userinfo, fragments and nonstandard ports remain rejected. Added regressions
cover the European QR flow, TLS-preserving redirects, dropping explicitly supplied
cookies across redirects, and rejection before QR rendering/polling for unlisted hosts.
All 101 offline tests, Ruff and Bandit pass locally. Full authenticated login and device
retrieval still require the user's own interactive Pi session.

This document records reproducible checks. No real Xiaomi credentials, device records
or session data are included in this repository or its CI.

Initial target inspection: Raspberry Pi 4, aarch64, Python 3.12.3, `venv` available,
13 GiB free on the home filesystem. No system package updates, service/container
changes or system Python modifications are required.

Live Xiaomi authentication and device/token retrieval: **not yet performed**. The user
must run `mi-home-cli login --region de` directly in their interactive Pi terminal and
approve the QR (or use the password/CAPTCHA/2FA alternative). An installed CLI or mocked
successful response is not evidence of a live successful cloud login.

See the pull request for final test counts, review findings, CI status and the exact
installed revision. Offline tests exercise authentication failures, QR timeout,
CAPTCHA and 2FA limits, rate limits, TLS/network errors, redirect restrictions, region
selection, missing fields, redacted output, export permissions and session safety.

Pre-install code review completed in the development session. The existing independent
review service rejected this new repository with `review_repository_not_allowlisted`;
no independent model approval is claimed. Review fixes include rejecting getpass echo
fallback, avoiding blocking reads of non-regular session files, accepting null empty
device lists, and falling back to v2 when the legacy discovery endpoint is unsupported.
These behaviors have regression tests. At this point 88 tests pass with 88% statement
coverage; Ruff, Bandit and dependency auditing are clean. Initial GitHub CI passed
Python 3.11–3.14. Its Gitleaks download failed with HTTP 504, so secret scanning uses
PyPI's detect-secrets with online verification disabled. Scan reports contain only
hashed candidates, and CI prints paths rather than candidate values.

## Raspberry Pi 4 result (2026-11-08)

Installed reviewed code revision `487ae1e662656f416fed95a61d761d08bee2fdc6` as a
non-editable package in `/home/nikita/.local/share/mi-home-cli/venv`, with launcher
`/home/nikita/.local/bin/mi-home-cli` and source checkout `/home/nikita/mi-home-cli`.
System Python, services and containers were not changed. The runtime venv contains
only the package, its runtime dependencies and pip; test tools ran in a separate
temporary venv which was removed afterwards.

On the Pi, all **88 tests passed in 1.82 seconds**. Installed version `0.1.0`, root
help and every subcommand's help passed; `pip check` found no broken requirements.
An isolated empty-state smoke check returned the expected login-required message.
No real account state was read or written. The code revision above also passed all
five GitHub CI jobs: Python 3.11, 3.12, 3.13, 3.14, and security.

The remaining user step is interactive live authentication and discovery:

```sh
~/.local/bin/mi-home-cli login --region de
~/.local/bin/mi-home-cli devices list --model zhimi.heater.mc2
~/.local/bin/mi-home-cli devices show DEVICE_DID --region de --homey --reveal-token
```

If the heater is missing, use `devices list --region all --model zhimi.heater.mc2`.
If QR login is rejected, try `login --method password --region de`. Enter credentials
and verification answers only on the Pi. Do not upload QR/session/token output to PRs
or paste it into an agent conversation. Report only success or the sanitized error.
