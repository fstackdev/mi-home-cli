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
