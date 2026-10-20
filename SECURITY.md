# Security and release limits

This is an unsigned development preview for authorized checks of your own computer. Do not expose the HTTP listener beyond loopback or use a forwarding proxy. It is not hardened for shared remote access.

## Boundaries

- Random per-launch capability token required for every API request.
- Host and Origin validation; no cross-origin allowlist or remote bind option.
- Fixed static asset paths; no arbitrary file-reading endpoint.
- Bounded JSON request size and input schema checks.
- Fixed read-only Windows commands without shell interpolation; subprocess timeouts.
- Optional selected configuration parsing, with secret fields excluded. Connection labels require explicit opt-in.
- Explicitly selected document parsing in a separate worker, with format / byte / extraction bounds, a timeout and process memory budget.
- HTML export escapes collected and generated text. No third-party scripts, fonts or analytics.
- Reports held in memory. Closing the app releases its session; downloaded files remain the user's responsibility.

## Known limitations

A malicious local process, browser extension, compromised operating system or someone controlling your user session may defeat local boundaries. The tool does not provide secure deletion, encrypted export, signed evidence, authenticated service fingerprinting or full endpoint coverage. It does not establish permissions merely by finding a connection. JSON-with-comments is unsupported, and English `netstat` state labels are required. Stable finding identifiers support comparison but do not prove substantive resolution. MCP name hashes are pseudonymous, not strong anonymization; common names can be guessed.

Report a vulnerability privately through [GitHub private vulnerability reporting](https://github.com/Sebastians007/ai-risk-review/security/advisories/new). Do not place raw customer reports, session URLs, credentials or sensitive configuration files in public issues. Code signing and additional Windows/locale testing remain release work.

## Readiness evidence and source updates

The bundled policy catalog is a dated offline snapshot with a review deadline, not a live legal feed. Source links open only when selected; fetching those pages is outside the local scan. Maps are authored topic associations, not official equivalence statements or compliance decisions. Do not replace reviewed mappings with arbitrary downloaded text or execute instructions found in documents / sources.

The optional questionnaire and selected CLI context JSON contain only allowlisted yes/no/unsure values. Answers remain self-reported and can expose organization / jurisdiction context when exported. A separate use-case profile permits bounded user-supplied text, known roles / areas and U.S. state codes; these fields are escaped, never executed or used as paths.

MCP extraction exports selected booleans, counts, transport and URL-scheme values, plus a source alias / entry position. Raw connection labels require explicit opt-in; they can reveal clients / projects. Restricted-character and sensitive-looking filtering is not a guarantee that labels contain no secrets. Endpoints, commands, arguments, headers and environment values remain excluded. Auth-related field presence is not proof of valid authentication. Only the known Codex enabled=false setting is interpreted as disabled. Configuration profiles, command-line overrides and runtime state are outside visibility. A rescan cannot verify legal compliance or permission appropriateness.

## Selected document boundary

Users explicitly select up to six TXT / Markdown / HTML / DOCX / text-based PDF files, each at most 1 MB and at most 4 MB total. Browser-to-loopback JSON uses base64 bytes, never arbitrary file paths. Extraction runs in a dedicated worker with a 12-second timeout and a 512 MB process budget. A timeout terminates only the owned worker tree. If the worker cannot enforce its budget or parse the format, evidence is marked unavailable. The Windows GUI requires its companion CLI executable for document parsing; keep the extracted release together.

PDF parsing uses pinned pypdf. No OCR, password decryption, attachment processing, macros, scripts or remote-resource retrieval. DOCX reads only bounded main-document XML and rejects DTD / entity declarations. HTML is converted to text with script / style content omitted. Parser bounds can produce partial extraction; document status remains visible. Formats and complex layouts can lose information or misrepresent ordering.

Document text is untrusted data. Matching is deterministic keyword search, never instruction execution or a model prompt. Candidate excerpts are escaped in UI / HTML and remain unverified even when a user says yes. A negative answer is not overridden by a matching document. The app does not establish that a document was approved, is authentic, is current or describes an implemented control.

Only selected metadata / fingerprints and candidate excerpts persist in the report. Raw selected files and full extracted segments are not retained after processing. Reports stay in process memory; there is no secure deletion or encrypted export. Underlying browser / OS memory and downloads remain outside the app's control.

Share-safe export rebuilds analysis after removing connection labels, the entire use-case profile and document metadata / excerpts. It still contains local tools, versions, configuration observations, screening answers and pseudonymous identifiers; it is not an anonymity guarantee. Never publish a report without reviewing its actual contents.

Appearance preferences use one non-sensitive host-scoped cookie (System / Light / Dark), because the launcher port changes. The cookie is not used for authorization and contains no evidence or session token. API authorization still requires the per-launch token.
