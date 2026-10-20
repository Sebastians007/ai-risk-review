# v0.4: evidence workspace and complete visual redesign

Approved scope: implement the four improvements recommended after the user's v0.3 report and replace the theme using their white / blue / navy security-dashboard reference.

1. Add a bounded selected-document pipeline for text, Markdown, HTML, DOCX and text-based PDF. Extract page / paragraph / line references locally, offer keyword-matched candidate evidence, and never treat text matches as proof or execute embedded instructions. Keep file parse failures visible.
2. Add one per-run use-case profile (purpose, system role, sector and affected states). Derive screening hints only from explicit answers. Support multiple states; preserve unresolved scope and other unmapped jurisdictions.
3. Add an explicit opt-in for local connection names. Raw commands, arguments, full URLs, tokens and credential values remain excluded. Provide a share-safe export that rebuilds the report without profile text, names or document details.
4. Summarize review priorities and real evidence counts first. Reference observations / document excerpts once instead of repeating them across every mapping. Keep candidates, reported assertions and unknowns distinct.
5. Replace all main UI surfaces and HTML export styling. Preserve token / origin protections, offline operation, baseline behavior, accessibility and source-catalog limits.
6. Test the evidence boundaries and report redaction; verify desktop / mobile browser flows, uploads, filters and packaged executables. Update docs and app plan, package v0.4 separately, then publish the verified prerelease.

Document limits: 6 explicitly selected files, 1 MB each / 4 MB total, bounded extraction, parsing in a worker with a timeout. No OCR, encrypted documents, macros, remote references or embedded attachment processing. No broad document-directory scan. Document matches are candidate excerpts only and require review.
