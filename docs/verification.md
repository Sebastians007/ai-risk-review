# v0.1 development verification

Verified locally on Windows 11 with Python 3.14.5 and PyInstaller 6.22.2.

- 20 unit tests: narrow matching, generic-port false positives, IPv6 parsing, confidential-value exclusion, rule evidence, unknown states, escaping, comparisons, request validation, Host/Origin/token boundaries, and sample/live baseline isolation.
- Browser demo flow: scope selection, empty-scope validation, context answers, four illustrative findings, HTML/JSON downloads, imported-baseline comparison, refresh and session continuity, desktop/mobile overflow, no page errors or external resource requests.
- Live Windows collectors: installed-app registry and local process/listener checks completed on the development host; MCP configuration collection was not run on live private settings. Synthetic fixtures exercise its extraction and secret exclusion.
- Packaged Windows executable: sample CLI scan, local HTTP interface with bundled HTML/JS/CSS, and live installed/listener CLI check completed.
- A separate read-only reviewer reran the initial 18-test suite and found no blocking issues. Two further boundary tests passed afterward. Pseudonymous identifier limitations are documented.

This is local development evidence, not a broad compatibility or security certification. Independent testing across Windows configurations, locales, browser environments and representative AI installations remains necessary before a stable public release. The binary is unsigned. No GitHub release has been published.

Ruling: initial discovery uses process-associated listener records, without network probes. This narrows deployment assumptions and avoids inference from port numbers; it sacrifices service fingerprinting and remote visibility.

Ruling: runtime reports are in-memory JSON rather than a persistent database. This keeps the first release portable and reduces retention complexity; users must export a report to compare another run.
