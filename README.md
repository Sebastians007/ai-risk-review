# AI Risk Review

A downloadable Windows evidence workspace for nontechnical AI readiness reviews. Discover supported tools, add selected documents and context, follow evidence into work packages, and save a report. No account, cloud model or paid API is required.

**v0.4.1 development preview.** Selected discovery and framework coverage, not an organization-wide audit, complete U.S. legal crosswalk or compliance certification.

## Download and run

1. Download the [v0.4.1 Windows ZIP](https://github.com/Sebastians007/ai-risk-review/releases/download/v0.4.1/AI-Risk-Review-v0.4.1-windows-x64.zip) from the [prerelease](https://github.com/Sebastians007/ai-risk-review/releases/tag/v0.4.1).
2. Extract the entire ZIP. **Keep AI-Risk-Review.exe and AI-Risk-Review-CLI.exe together**: the GUI uses the companion CLI for bounded document parsing.
3. Open AI-Risk-Review.exe. Choose checks, add optional profile / answers / documents, then run.
4. Review the overview, inventory, evidence library, readiness work and source limits.
5. Save a local HTML / JSON report or a share-safe HTML report. Use **Close app** when done.

Local builds are in dist/v0.4.1/. Older versioned builds remain; the root dist/ executable is v0.1. Executables are unsigned development previews. Follow Windows / organization software policies. Closing the browser tab alone does not immediately stop the process; inactive sessions expire after 30 minutes.

## Appearance

Use **Appearance** in the top bar to choose System, Light or Dark. System follows the operating system. Your explicit choice is stored as a non-sensitive browser cookie so it works across the launcher’s changing local ports. Blocking or clearing cookies resets the choice. This preference contains no report data. Exported reports retain their reading / print layout. [Dark-mode preview](docs/images/v041-dark-desktop.png).

## New in v0.4

- Complete white / blue / navy dashboard redesign, responsive navigation and matching HTML reports.
- Actual collection counts and prioritized actions, without a security percentage.
- One optional profile per review: purpose, role, area and multiple affected U.S. states.
- Relevant follow-up prompts, with a switch to show all questions. Unknown remains unknown.
- Explicit opt-in for supported MCP connection labels in local reports.
- Selected documents with candidate excerpts and page / paragraph / line references.
- Searchable evidence, work-package filters and references instead of repeated observations.
- Share-safe export rebuilt without connection labels, profile or document names / excerpts.
- Matching CLI profile, document and export options.

[Desktop preview](docs/images/v04-overview-desktop.png) · [Mobile preview](docs/images/v04-overview-mobile.png)

## Discovery coverage

Supported traditional uninstall records and current-user Windows packages; recognized process names / counts; English Windows TCP listener records matched to supported process names; optional fixed MCP JSON / Codex TOML settings; optional presence checks for seven named tool directories.

Generic names or ports never establish AI identity. No executable paths, command lines, environment inventory, conversations, browser history, subnet scan, network probes or remediation. Process names can be spoofed. Supported versions are installation facts, not vulnerability assessments.

MCP exports source alias, entry position, transport, selected booleans and list counts. Raw commands, arguments, full URLs, credential values, headers and environment values remain excluded. Connection labels are omitted by default and can reveal customer / project names when explicitly enabled. Restricted-character / sensitive-looking label filtering is not a comprehensive secret detector. Only known Codex enabled=false semantics establish configured disablement; profiles and runtime overrides remain unverified. Auth-field absence does not establish missing authentication; an undeclared tool list does not mean zero permissions.

Browser-only services, SaaS, private accounts, other users, unsupported tools and remote hosts can be missed. Complete collection means selected checks ran, not complete organizational coverage.

## Selected documents

Choose up to **6 files, 1 MB each / 4 MB total**: UTF-8 TXT / Markdown / HTML, DOCX or text-based PDF. Files are parsed locally in a worker with a 12-second timeout and 512 MB process memory budget. Keep both executables together; if the parser cannot run safely, document extraction is unavailable.

Limits: at most 100 PDF pages, 1,000 retained segments, 160,000 retained characters per file and 6,000 characters per segment. Extraction may be partial. No OCR, decryption, macros, attachment processing, script execution or remote fetching. DOCX main-body text is read; headers, footnotes, comments and image-only content can be missed. HTML locators are extracted text blocks, not original HTML line numbers; PDF page numbers are physical pages, not necessarily printed labels.

Keyword matching offers up to two excerpts per work package per document. Every excerpt is a **candidate requiring review** for context, negation, dates, approval, actual implementation and sufficiency. No match does not prove missing evidence. Document instructions never execute or change rules.

Only document metadata / fingerprints and candidate excerpts enter the report. Full extracted segments are discarded after candidate generation. Source files remain unchanged. Avoid unnecessary sensitive records.

**Demo mode replaces local discovery only; explicitly selected documents are still parsed locally.**

## U.S. readiness coverage

12 selected primary-source entries and 12 authored evidence work packages, reviewed October 19, 2026: NIST AI RMF / GenAI Profile; OMB M-25-21, M-25-22 and M-26-04; selected FTC, EEOC ADA and HIPAA cloud issues; Colorado SB26-189; California ADMT regulations; Texas HB149; NYC Local Law 144.

Not all U.S. frameworks / laws / policies, the full NIST framework or an official equivalence crosswalk. Internal policies and contracts need their own review. Unmapped sectors / jurisdictions are explicitly listed. Packages link evidence and define missing artifacts, suggested owner roles, deliverables and verification.

Screening matches mean potentially relevant, not legally applicable. Negative answers are not exemptions. Explicit profile selections supply positive CA / CO / TX and employment hints unless an answer overrides them. New York does not establish NYC, health care does not establish HIPAA, and government does not establish federal work.

The offline catalog shows a 30-day scheduled review deadline, then review overdue. It does **not** check live legal updates; sources can change inside the window. No package is marked independently verified or compliant.

## Reports and privacy

The app binds only to 127.0.0.1, requires a random per-launch API token and validates Host / Origin. Do not share the private launch URL or forward the port. No telemetry, cloud API, inference request or automatic fixes.

Reports remain in memory until replaced / the app exits, or until you save a copy. Browser extensions, sync and downloads are outside app control. Downloads are unencrypted.

- **Local reports** can contain optional connection labels, profile details, document names, fingerprints and excerpts.
- **Share-safe reports** rebuild analysis without those details. Tools, versions, security observations, screening answers and pseudonymous connection identifiers remain. They are not guaranteed anonymous or suitable for public posting.

Finding-ID comparison supports older schema-1 reports. A missing ID is not verified resolution; scope, access and answers can change. Observation IDs belong to one report. Sample / live discovery cannot be compared. Evidence is not cryptographically signed.

## Terminal use

    .\AI-Risk-Review-CLI.exe scan --html report.html --json report.json
    .\AI-Risk-Review-CLI.exe scan --integrations --connection-names --profile profile.json --context context.json --evidence policy.pdf --html local.html
    .\AI-Risk-Review-CLI.exe scan --evidence policy.docx --share-safe --html share.html --json share.json

Repeat --evidence for multiple files. Templates: examples/profile-template.json and examples/context-template.json. --locations adds named-directory checks. Profile / context JSON files are allowlisted and at most 64 KB. --connection-names requires --integrations. Legacy --scan --output report.json remains supported.

Outputs must be distinct new files with existing parent folders. Exit 0 means selected collection / extraction finished, not safety. Exit 2 means invalid inputs / outputs or partial / unavailable evidence; an incomplete report may still be saved with limits.

## Source and build

Python 3.11+ on Windows. Core uses the standard library; PDF extraction uses pinned pypdf.

    python -m pip install -r requirements.txt
    python app.py
    python app.py --demo
    python app.py scan --demo --evidence examples/demo-ai-policy.txt --html demo.html
    python -m unittest discover -s tests -v
    python -m venv .venv-build
    .\.venv-build\Scripts\python.exe -m pip install -r requirements-build.txt
    .\build.ps1

Build uses .venv-build when present to avoid bundling unrelated installed packages. It runs tests, bundles both executables / web assets and creates ZIP / SHA-256 under releases/. Outputs are environment-specific. Third-party licenses are in licenses/ and THIRD_PARTY_NOTICES.txt.

## Project and contribution

Collectors: collectors.py. Profiles / documents / privacy: workspace.py. Catalog: crosswalk.py. Findings / comparison: core.py. HTML: reporting.py. HTTP / CLI: app.py. Interface: web/.

See [v0.4 plan](docs/v04-plan.md), [verification](docs/v04-verification.md), [app plan](docs/app-plan.html) and [security notes](SECURITY.md). Report vulnerabilities through [private security reporting](https://github.com/Sebastians007/ai-risk-review/security/advisories/new), without customer reports or credentials in public issues.

Future: multiple use cases / organizations, reviewer decisions, richer matching, additional sector / jurisdiction packs, reviewed source updates, authorized enterprise connectors, signing and broader compatibility validation.

Related tools: [Julius](https://github.com/praetorian-inc/julius), [Shadow AI Guard](https://github.com/AmanSK5/shadow-ai-guard), [Nexus ShadowScan](https://github.com/aisecnomad/Nexus-ShadowScan), [Apotrope](https://github.com/hexorcist404/apotrope). No first-of-kind claim; their code is not bundled.

MIT. Maintained by [Sebastians007](https://github.com/Sebastians007).
