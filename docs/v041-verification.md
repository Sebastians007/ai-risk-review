# v0.4.1: appearance verification

- Added System / Light / Dark selection to the top bar. Theme resolves before the stylesheet paints; system mode listens for OS appearance changes.
- One non-sensitive preference cookie persists across the launcher's changing loopback ports. It contains no token or evidence and does not authorize API requests. Blocked storage falls back to the current session / system preference.
- Full 49-test suite passes. Both Windows binaries built in the clean environment.
- Browser verification against two packaged instances passes: system default, explicit switching, reload persistence, persistence across distinct local ports, OS-change handling, dark-mode review flow, mobile overflow and no page errors.
- Desktop and mobile dark captures inspected. Main dark text / control pairs measured at 6.01:1 or above; accent icon on its tinted surface measured at 5.72:1. Design detector reported no low-contrast flags.
- Exported reports retain their existing reading / print appearance. Theme choice does not enter evidence or change analysis.
