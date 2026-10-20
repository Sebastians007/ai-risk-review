# Security and release limits

This is an unsigned development preview for authorized checks of your own computer. Do not expose the HTTP listener beyond loopback or use a forwarding proxy. It is not hardened for shared remote access.

## Boundaries

- Random per-launch capability token required for every API request.
- Host and Origin validation; no cross-origin allowlist or remote bind option.
- Fixed static asset paths; no arbitrary file-reading endpoint.
- Bounded JSON request size and input schema checks.
- Fixed read-only Windows commands without shell interpolation; subprocess timeouts.
- Optional selected JSON parsing, with sensitive fields excluded from results.
- HTML export escapes collected and generated text. No third-party scripts, fonts or analytics.
- Reports held in memory. Closing the app releases its session; downloaded files remain the user's responsibility.

## Known limitations

A malicious local process, browser extension, compromised operating system or someone controlling your user session may defeat local boundaries. The tool does not provide secure deletion, encrypted export, signed evidence, authenticated service fingerprinting or full endpoint coverage. It does not establish permissions merely by finding a connection. JSON-with-comments is unsupported, and English `netstat` state labels are required. Stable finding identifiers support comparison but do not prove substantive resolution. MCP name hashes are pseudonymous, not strong anonymization; common names can be guessed.

Report a vulnerability privately through [GitHub private vulnerability reporting](https://github.com/Sebastians007/ai-risk-review/security/advisories/new). Do not place raw customer reports, session URLs, credentials or sensitive configuration files in public issues. Code signing and additional Windows/locale testing remain release work.

## Readiness evidence and source updates

The bundled policy catalog is a dated offline snapshot with a review deadline, not a live legal feed. Source links open only when selected; fetching those pages is outside the local scan. Maps are authored topic associations, not official equivalence statements or compliance decisions. Do not replace reviewed mappings with arbitrary downloaded text or execute instructions found in documents / sources.

The optional questionnaire and selected CLI context JSON contain only allowlisted yes/no/unsure values. Answers remain self-reported and can expose organization / jurisdiction context when exported. No policy documents are ingested in this preview.

MCP extraction exports selected booleans, counts, transport and URL-scheme values, plus a source alias / entry position. Raw connection names, endpoints, commands, arguments, headers and environment values remain excluded. Auth-related field presence is not proof of valid authentication. Only the known Codex enabled=false setting is interpreted as disabled. Profiles, command-line overrides and runtime state are outside visibility. A rescan cannot verify legal compliance or permission appropriateness.
