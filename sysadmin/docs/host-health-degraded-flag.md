# exec-degraded flag (host-watch)

`host-watch` (`sysadmin/cmd/host-watch`) writes this flag while the host cannot reliably start non-Apple code. That happens when syspolicyd crashes, is throttled or restarts, when an exec of a non-Apple binary takes more than 5 s while an Apple control exec stays fast, or when 3 or more processes look held at exec.

## Location

There is exactly one path, with no override:

`$HOME/Library/Application Support/host-health/exec-degraded`

host-watch refuses to start when `--degraded-flag` names any other path. Consumers check only this path. The file is mode 0644, readable by the same user, and is published atomically through an exclusive temporary file and a rename.

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
- A consumer only reads the file and never writes or removes it. Before starting any new heavy lane, it checks for the file read-only, with an in-process stat or the shell builtin `test -e`, never by exec-ing another tool. It does not wait for a stall to appear first.
- Treat a file that exists but does not parse as present.

- A lane held by the flag is recorded as unable to start, never as run or passed.

While the incident lasts, host-watch re-publishes the flag on every tick if it is missing. It removes the flag only after `--clear-after` (10 min to 24 h; 10 min in the LaunchAgent) of continuous positive health: syspolicyd running, a fresh successful exec probe, and a successful `ps` scan without held execs. Missing or unknown evidence restarts that window. host-watch itself never kills, restarts or reconfigures anything else.
