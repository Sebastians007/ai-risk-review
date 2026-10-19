# AI Risk Review

A Windows-first, local AI checkup for people who want understandable findings and evidence. Download a portable release, launch it, choose read-only checks and save a report. No account, Python installation, Docker, paid API or language model is required by the packaged app.

**Status: v0.2.0 development preview.** Narrow, documented coverage. Not a compliance audit, proof of organization-wide shadow AI discovery, or a substitute for qualified review. This project is not claimed to be the first AI discovery tool.

v0.2 adds current-user Windows package records, running-app discovery independent of listening ports, opt-in Codex TOML, named-directory presence checks, a reconciled inventory and a dedicated terminal executable. It addresses the real v0.1 report that missed ChatGPT, Claude and Codex. Source-only identities and configuration presence remain observations, not proof of actual use or approval.

## Run the portable Windows build

1. Download and extract the [v0.2.0 Windows ZIP](https://github.com/Sebastians007/ai-risk-review/releases/download/v0.2.0/AI-Risk-Review-v0.2.0-windows-x64.zip) from the [prerelease page](https://github.com/Sebastians007/ai-risk-review/releases/tag/v0.2.0).
2. Double-click `AI-Risk-Review.exe`. A private local interface opens in your default browser. Locally built binaries are in `dist/v0.2.0/`; the earlier root `dist/` executable is the old v0.1 preview.
3. Choose checks, optionally add context, then run the checkup.
4. Review coverage and findings. Save the HTML report to read or print, and JSON for a future comparison.
5. Use **Close app** when done. Closing the browser tab alone does not immediately stop the local process; an inactive session expires after 30 minutes.

The development executable is unsigned. Windows may show an unrecognized-publisher warning. Public release signing and broader compatibility validation remain future work. Do not bypass your organization's software policies.

## What it checks

- **Installed applications:** Selected current-user and machine uninstall registry locations. Recognized names include Ollama, LM Studio, ChatGPT, Claude, Cursor, Windsurf, GPT4All, AnythingLLM, Cherry Studio and Jan. It does not enumerate every Store application, portable installation or browser service.
- **Windows packages:** Current-user `Get-AppxPackage` records matched to explicitly supported names, including Claude and OpenAI.Codex. It does not inspect other users or identify every package by keyword.
- **Running applications:** `Get-Process` names matched independently of listeners. Supported identities now include ChatGPT and Codex. Only recognized tool names and counts are retained, not command lines or environment values. Process names can be spoofed.
- **Local TCP listeners:** English Windows `netstat` records matched to a small set of recognized process names. Generic ports alone never identify AI. Non-loopback bindings produce a review item, not a claim of internet exposure. Authentication, remote reachability, firewall rules and application behavior are not tested. Process names can be spoofed, so these are identity hints, not cryptographic product verification.
- **Optional MCP settings:** Known Claude Desktop, Cursor, VS Code and Windsurf JSON paths, plus Codex `config.toml` under `CODEX_HOME` or the default `.codex` directory. Codex's explicitly declared `mcp_servers` table is parsed; plugin-managed connections and alternate profiles are outside visibility. JSON-with-comments is not parsed. Configuration file presence is reported even when no supported connections are declared. Only connection presence/type and explicit disabled state are extracted. Arguments, environment values, URLs, headers and raw connection names are not exported. Source files can contain secrets and are parsed in local memory when you explicitly select this option. Connection identifiers are pseudonymous hashes for repeat-run matching. Common names may be guessed by hashing candidates; these identifiers are not strong anonymization.
- **Optional known locations:** Presence checks for seven fixed tool directories, with no recursion or content inspection. An artifact may be a leftover and does not establish an active installation. Paths are not exported.
- **Optional context:** Three answers about work use, agreed rules and sensitive data. Findings based on these are labeled reported, never independently verified.

Unsupported tools, other users, SaaS-only use and restricted data sources may be missed. An unavailable check stays unavailable. No observed findings is not a clean bill of health.

## Privacy and behavior

The application makes no telemetry or cloud API calls. It binds to `127.0.0.1` on an available port. The launcher gives your browser a random per-session token; the interface keeps it in that tab's session storage. Do not share the private launch URL. Source observations and reports remain in process memory until the process exits or you download a report. The default browser and its extensions, sync, download history and caches are outside this application's control. Downloads are not encrypted by the app: save them in a suitable location and review before sharing.

No conversations, arbitrary user documents, environment-variable inventories or browsing history are collected. There are no subnet scans, network probes, exploit attempts or remediation changes. The collectors run read-only Windows commands with bounded timeouts. Administrator rights are not requested.

## Comparison

Import a previously exported JSON report before a new check. The app compares finding identifiers and reports new, matching and no-longer-observed items. It does not declare a missing finding resolved: scope, access or user answers may have changed. Sample and live reports cannot be compared. Reports are not cryptographically signed; compare only reports you trust.

## Run from source

Python 3.11+ on Windows; runtime uses the standard library. Development was verified on Python 3.14.5 / Windows.

```powershell
python app.py
python app.py --demo
python app.py --scan --output my-checkup.json
python app.py --scan --integrations --output my-checkup-with-mcp.json
python app.py scan --html report.html --json report.json
python app.py scan --integrations --locations --html full-report.html --json full-report.json
python -m unittest discover -s tests -v
```

`--scan` is the explicit authorization to collect the selected local records. `--demo` uses illustrative data and does not inspect the computer. CLI output files are created exclusively; existing files are not silently overwritten. Use `--no-browser` to print a private local session address for manual opening.

For the packaged terminal experience, open PowerShell in the extracted release folder:

```powershell
.\AI-Risk-Review-CLI.exe scan --html report.html --json report.json
```

Add `--integrations` or `--locations` to opt into those checks. Exit code 0 means selected collectors finished, not that the computer is safe. Exit code 2 means input/output validation failed or a collector was partial/unavailable; an incomplete report can still be exported with its limitations. The GUI executable supports report-writing flags too, but use the CLI executable for visible terminal output. Output paths must be distinct new files with existing parent folders.

## Build

```powershell
python -m pip install -r requirements-build.txt
./build.ps1
```

Build tooling is pinned independently of the dependency-free runtime. Run the build from this project folder on Windows. The script runs tests, packages the web assets with PyInstaller and creates a ZIP plus SHA-256 checksum under `releases/`. Build results are environment-specific; rebuilding need not produce byte-identical files.

## Design and contribution

`core.py` contains deterministic findings and escaped report rendering; `collectors.py` handles evidence; `app.py` protects the local HTTP boundary; `web/` is the guided interface. See `docs/implementation-plan.md` and `SECURITY.md`.

Add collectors through fixtures and documented limits, not broad name/port guesses. Test generic-port false positives, restricted access, malformed files and secret exclusion. Every finding needs an evidence statement, an uncertainty statement, a concrete action and a way to check improvement.

Related projects worth studying include [Julius](https://github.com/praetorian-inc/julius), [Shadow AI Guard](https://github.com/AmanSK5/shadow-ai-guard), and [Nexus ShadowScan](https://github.com/aisecnomad/Nexus-ShadowScan). This implementation was written for this project; no code from those repositories was incorporated.

[Apotrope](https://github.com/hexorcist404/apotrope) informed the modular terminal-auditor direction. This app does not bundle it or copy its checks; it implements a smaller AI-focused discovery workflow.

License: MIT. Maintained by [Sebastians007](https://github.com/Sebastians007).

The [app plan](docs/app-plan.html), [v0.2 implementation plan](docs/v02-plan.md) and [verification record](docs/v02-verification.md) document the direction and tested limits. Download the HTML plan to open it in a browser. Windows builds are published as development prereleases, not signed stable releases.
