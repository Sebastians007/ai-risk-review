# v0.3 verification

Verified October 19, 2026 (local time), on Windows 11 / Python 3.14.5.

- 39 unit / integration tests pass, including unknown evidence, reported assertions, paired applicability triggers, stale-source warnings, HTML escaping, secret exclusion, unsupported disable flags, entry locators, CLI context validation and existing local-API security / output handling.
- `node --check web/app.js` passes.
- Browser automation against source and the frozen CLI-hosted app passes: no-selection validation, grouped questionnaire, NYC/employment screening, 4 expected demo findings, 12 source entries, 12 evidence work packages, HTML / JSON downloads, baseline comparison, refresh, shutdown, desktop / mobile overflow, no page errors and no external requests during the workflow. Primary-source links were not clicked in this no-network test.
- Both frozen GUI and CLI executables produce valid demo HTML / JSON with the v0.3 crosswalk and selected context template.
- PyInstaller GUI / CLI builds and release ZIP / checksum creation pass. Prior versioned builds remain available locally.
- Fresh independent code review found unsupported per-client disable handling and an entry-number locator issue. Both were fixed, regression tested and re-reviewed. No remaining important or critical findings were identified by that review.
- Only illustrative sample reports are included. Actual user reports, local configuration and session URLs are excluded from source / release examples.

Catalog scope: 12 selected primary-source entries, reviewed October 19, 2026, with a 30-day scheduled review window. It is an offline snapshot and can become outdated before that window ends. NIST subcategory mappings support only portions of their outcomes; other associations are explicitly topic-level. No full framework implementation, complete U.S. legal coverage, legal applicability decision, independent evidence validation or compliance certification is claimed.

Remaining product work: selected policy / evidence document ingestion, per-use-case and multi-jurisdiction profiles, additional state / sector / standards packs, reviewed updates, enterprise connectors, signed releases and broader Windows compatibility validation.
