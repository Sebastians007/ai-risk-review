# v0.4 verification

Verified October 19, 2026 local time on Windows 11 / Python 3.14.5.

- 49 unit / integration tests pass in the clean build environment, including legacy discovery / API boundaries, input bounds, opt-in labels, report redaction, HTML script exclusion, DOCX references, actual isolated text-PDF extraction, profile screening and CLI parity.
- Node syntax check passes. Fresh independent review findings (reference-function shadowing, profile visibility and outdated provenance wording) were fixed and rechecked. No remaining important / critical findings were identified in that review.
- Browser workflow passes against the final frozen CLI-hosted app: scope validation, grouped follow-up questions, multiple-state profile, document upload / candidate citations, source screening, evidence search, control filters, local HTML / JSON, share-safe HTML, baseline comparison, refresh and shutdown.
- Desktop (1440px) and mobile (390px) screenshots inspected. Functional overflow checks pass after fixing long document-fingerprint wrapping. Text sizes and green-label contrast were improved following the mechanical design check. The user-supplied dashboard reference governs the chosen white / blue / navy surfaces and icon treatment.
- No page errors or external requests during the tested workflow. Fonts load from the packaged local server; primary-source links were not clicked in this no-network workflow test.
- Both frozen GUI and CLI executables pass profile + selected TXT / PDF extraction, page citation and HTML / JSON export tests. Frozen CLI share-safe JSON excludes the profile, selected document names / excerpts and opted-in connection labels used as test canaries.
- Build uses a clean local environment with pinned PyInstaller 6.22.2 / pypdf 6.21.1. Optional image / numerical / cryptographic packages are excluded; encrypted and image-only document processing is unsupported. Both executables are about 11 MB and must stay together for GUI document parsing.
- ZIP / checksum generated; only illustrative sample documents / reports and sample-mode screenshots are included. Actual user reports and configuration files are excluded.

The source catalog remains the selected 12-source offline snapshot reviewed October 19, 2026. This release does not expand it into complete U.S. legal coverage. Document matching remains bounded keyword retrieval, not semantic verification, policy approval validation or evidence sufficiency assessment. One run has one optional use-case profile; an organizational / multi-use-case system is future work. Windows signing and broader platform / locale validation remain future work.
