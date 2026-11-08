# Validation

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
