# v0.2 verification

Verified on this Windows 11 development host with Python 3.14.5 and PyInstaller 6.22.2.

- All 29 unit tests pass, including package/process matching, generic-port false positives, confidential-value exclusion from Codex TOML, inventory reconciliation, CLI output collision/overwrite guards and existing local API security tests.
- Guided browser checks pass: collection selection, empty-scope error, context answers, findings, HTML/JSON download, imported baseline comparison, refresh, desktop/mobile overflow, and no page errors or external requests.
- Live source acceptance finds ChatGPT through running processes, Codex through Windows package and running-process records, and Claude through its Windows package. Selected configuration/location checks also completed; raw private configuration values were not exported or logged.
- Packaged console executable passes sample and live scans with both HTML/JSON output. Live packaged inventory contains ChatGPT, Claude and Codex.
- Packaged browser executable passes legacy CLI compatibility and serves its updated embedded HTML/JS/CSS.
- Separate read-only code reviewer reran all 29 tests and found no blocking issue. Reviewer did not independently scan private settings or repeat packaged acceptance.
- v0.1 ZIP and executable remain preserved. v0.2 GUI/CLI binaries are under `dist/v0.2.0/`; release ZIP and checksum are under `releases/`.

This evidence is local development validation, not broad platform certification. Detection signatures are narrow; package names and process names are identity hints. Coverage does not establish actual use, approval, credentials, vendor terms, internet reachability or compliance. Development binaries remain unsigned. The checks above were completed before GitHub publication; see the repository releases for published preview downloads.
