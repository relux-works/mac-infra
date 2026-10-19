## Unified log

Source: subsystem `com.apple.ALF.ApplicationFirewall`, process `socketfilterfw`.
- Category `fw` carries the per-flow decisions:
  - `Handle flow with processPID: N and bundleid: X`
  - `KNOWN APP FLOW: <path>, return known verdict: N`
- Pull: `/usr/bin/log show --last 7d --info --debug --predicate 'process == "socketfilterfw" OR subsystem == "com.apple.alf"'`.
  - In zsh, plain `log` is a builtin; use `/usr/bin/log`.
- Retention: `fw` lines exist only for 2026-10-18 and 2026-10-19 (298 + 25). History is short, so a watchdog must stream rather than read history.
- Flow decisions in the window: 25, all verdict 1 (allow), 0 denies.

| App | Flows |
| --- | ---: |
| ControlCenter | 16 |
| rapportd | 4 |
| replicatord | 4 |
| netbiosd | 1 |

Interpretation:
- Nothing is being blocked now. With 0 blocked entries and signed auto-allow on, ALF blocks only unsigned or unlisted code that wants to accept inbound connections.
- macOS normally shows a GUI prompt for such code. If the owner clicks Deny, the app becomes a blocked entry.
- With stealth off, probes to closed ports get an RST and are not logged as app events.

## Not visible
