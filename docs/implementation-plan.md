# AI Risk Review v0.1 Implementation Plan

**Goal:** A Windows-first portable, open-source local AI checkup with a nontechnical interface, explainable findings, JSON/HTML export and repeat-run comparison.

**Architecture:** Python standard-library collectors and deterministic rules; loopback-only HTTP server with a per-launch capability token; embedded browser interface. No accounts, model, remote assets or telemetry. Reports stay in memory until downloaded by the user.

**Constraints:** Read-only checks. No installation changes or automatic remediation. No subnet scans. Local HTTP probes use fixed read-only paths and candidate ports only. Configuration inspection is opt-in; never export command arguments, environment values, credential fields or full personal paths. Missing access and collection failures stay visible.

**Files:** `core.py` models/rules/comparison/export; `collectors.py` Windows observations; `app.py` authenticated local server and CLI; `web/index.html` guided UI; `tests/` rule, collector and HTTP boundary checks; `build.ps1` portable packaging; README, license and security documentation.

## Tasks

- [x] Write and run failing checks for evidence-based classification, unknown states, report escaping, comparisons and server authentication.
- [x] Implement collectors with bounded subprocess and HTTP timeouts; confirm service identity independently of port number.
- [x] Implement rules, report export and conservative before/after comparison.
- [x] Implement authenticated loopback server and guided browser interface.
- [x] Run tests and browser workflow checks, including mobile, scan failure, export and baseline comparison.
- [x] Package Windows executable, run a CLI smoke check of the executable and document release limitations.

## Review focus

False AI identification from generic ports; inaccessible records presented as absent; confidential values leaking through configuration extraction or errors; malicious baseline/report text; unauthorized local HTTP requests; reports implying internet exposure, business use or compliance without evidence.

## Acceptance

A user can open the app, review collection scope, run supported checks, understand the results and download HTML/JSON without Python or an LLM installed. Each finding has stable identity, evidence, limitations and a concrete next step. A prior JSON report can be compared, with absent findings labeled no longer observed rather than automatically resolved. Packaged releases remain unsigned development previews until release-signing is arranged. GitHub publication is separate from the local build.


Verification evidence and scope rulings: see `verification.md`. Public publication, code signing and broader compatibility testing remain outside this local preview.
