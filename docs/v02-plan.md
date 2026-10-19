# v0.2 discovery update

User approved terminal-backed discovery modeled on a modular local auditor, while keeping the guided UI. No Apotrope code or dependency is incorporated.

- Add current-user Windows package discovery and standalone process discovery.
- Keep registry and listener evidence separate; generic ports still never establish AI identity.
- Add opt-in Codex TOML and named-location presence checks; extract no credential values, raw connection names, command arguments or personal paths.
- Reconcile observations into a tool inventory without claiming actual use or approval.
- Surface per-source coverage, counts and limitations in reports.
- Add `scan --html ... --json ...` terminal workflow while preserving `--scan` compatibility. Package a separate console executable alongside the browser launcher.
- Test false positives, confidential-value exclusion, Windows live acceptance for ChatGPT/Codex/Claude, UI exports and both executable modes. Preserve the v0.1 ZIP.

Implementation order: failing parser and inventory tests, collectors, inventory/report/UI integration, CLI and validation, live discovery acceptance, packaging and final review.
