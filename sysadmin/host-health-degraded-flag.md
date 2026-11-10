# exec-degraded flag (host-watch)

`host-watch` (`sysadmin/cmd/host-watch`) writes this flag while the host cannot reliably start non-Apple code. That happens when syspolicyd crashes, is throttled or restarts, when an exec of a non-Apple binary takes more than 5 s while an Apple control exec stays fast, or when 3 or more processes look held at exec.

## Location

The path is passed to host-watch explicitly with `--degraded-flag`. The LaunchAgent in `README.md` uses `~/Library/Application Support/host-health/exec-degraded`, and consumers read that path. The file is readable by the same user (mode 0644, written atomically with a temp file and a rename).

## Format

One JSON object followed by a newline, with exactly these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `reason` | string | The checks in alert, for example `syspolicyd.state=alert, exec.probe=alert` |
| `since` | string, RFC 3339 UTC | When the degraded state began |
| `host_watch_pid` | number | PID of the host-watch process that wrote the flag |

## Rule for consumers

- Flag present: do not start a new heavy lane (parallel `go test`, builds, test harnesses that build, sign or execute fresh binaries). Running work is not touched.
- Flag absent: proceed.
- A consumer only reads the file. It never writes or removes it. It checks for the file with an in-process stat or open, not by exec-ing another tool.
- Treat a file that exists but does not parse as present.

host-watch removes the flag after `--clear-after` (10 min in the LaunchAgent) of continuous health. host-watch itself never kills, restarts or reconfigures anything else.
