# sysadmin

Host administration tools for this Mac, kept as their own Go module (`github.com/relux-works/mac-infra/sysadmin`). They do not import mac-infra's internal packages.

## host-watch

`host-watch` is a watchdog for the exec-gate stall. When syspolicyd, the exec-policy daemon, crashes or is throttled, macOS holds every exec of non-Apple code: CLI tools, agent hooks and test runners hang, load climbs, and in the end the WindowServer main thread stops checking in.

The most common trigger is a burst of test binaries that are freshly built, re-signed or deliberately mis-signed and then deleted while syspolicyd is still scanning them.

| Check | Signal | Level |
| --- | --- | --- |
| syspolicyd | a new `syspolicyd-*.ips`, `.spin` or `.hang` (also in `Retired`), launchd state other than `running`, or `runs` growing | alert |
| exec latency | one exec per `--probe-every` of host-watch's own `--probe-exec`, timed against `/usr/bin/true`; at most one probe outstanding | warn > 2 s, alert > 5 s or still running after 15 s |
| held execs | `ps` rows older than 30 s with RSS ≤ 256 KB whose absolute binary path is outside the OS directories; bare argv[0] names and rows ps prints in parentheses do not count; the RSS threshold is not yet calibrated against a real stall | alert ≥ 3, critical ≥ 20 or rising for 3 ticks |
| GUI | new `WindowServer` crash or hang reports | alert, at most once per 5 min per class, held reports go out with the next alert |
| report sources | each configured directory and its `Retired` subdirectory are separate sources; configured directories may be symlinks (aliases); a source is seeded with its history on its first actual enumeration, and a missing `Retired` is not an enumeration | — |
| host tools | new crash reports of the binaries named by `--tool-report-prefixes`; a code-signing kill is labelled `(CODESIGNING)` | alert |
| resources | `kern.memorystatus_vm_pressure_level`, `vm.swapusage`, free space on `--data-volume`, and whether the `--fseventsd-watchdog-label` LaunchAgent is disabled or not loaded | alert only |

How it works:
- It observes with Apple binaries (`/bin/launchctl`, `/bin/ps`, `/usr/sbin/sysctl`) and in-process calls only, so it keeps working while the gate is shut.
- Every alert is written to `events.jsonl` and shown at once as a macOS notification.
- It is also sent to a2a as one notice at a time. a2a is a non-Apple binary, so while execs are degraded notices are queued and sent once the host is healthy again.
- Its only automatic action is the exec-degraded flag, described in [docs/host-health-degraded-flag.md](docs/host-health-degraded-flag.md). It never kills, restarts or reconfigures other processes, launchd jobs or protection settings.
- It writes a heartbeat file (RFC 3339) every tick.

If syspolicyd is stuck, the owner can run the recovery command:

```sh
sudo /bin/launchctl kickstart -k system/com.apple.security.syspolicy
```

### Build and test

```sh
cd sysadmin
go vet ./... && go test -race ./...
go build -trimpath -o ../.temp/host-watch ./cmd/host-watch
```

Install a copy at a stable path outside any checkout, named by its sha256, never a symlink into a working tree. A working-tree build that launchd starts can be refused by the exec policy while the host is under load, and the exec probe runs the installed binary itself:

```sh
sum=$(shasum -a 256 ../.temp/host-watch | cut -c1-16)
dir="$HOME/Library/Application Support/host-watch/bin"
mkdir -p "$dir" && cp ../.temp/host-watch "$dir/host-watch-$sum"
```

Point the LaunchAgent at `$dir/host-watch-<sum>` and record the sha.

### Run

Every input is an explicit flag; there are no defaults. `--once` observes only: one tick without the exec probe or any a2a post. `--dry-run` keeps its state in memory and never writes the state directory, the flag or a2a, so it can neither hide nor clear a live incident.

```sh
"$HOME/Library/Application Support/host-watch/bin/host-watch-SUM" \
  --reports-dirs /Library/Logs/DiagnosticReports,$HOME/Library/Logs/DiagnosticReports \
  --tool-report-prefixes mac-firewall,mac-infra-core,host-watch \
  --state-dir "$HOME/Library/Application Support/host-watch" \
  --degraded-flag "$HOME/Library/Application Support/host-health/exec-degraded" \
  --a2a "$HOME/.local/bin/a2a" --as AGENT --room ROOM --to RECIPIENTS \
  --data-volume /System/Volumes/Data \
  --fseventsd-watchdog-label works.relux.mac-infra-fseventsd-watchdog \
  --interval 15s --probe-every 60s --post-timeout 60s --clear-after 10m --notify
```

Install it as a user LaunchAgent, `works.relux.sysadmin.host-watch`, with `RunAtLoad`, `KeepAlive`, `ProcessType Background` and the arguments above. Give it `A2A_CONFIG_DIR` for the posting identity. Timing flags are bounded: `--interval` 1 s–60 s, `--probe-every` from `--interval` to 10 min, `--post-timeout` 1 s–60 s, `--clear-after` 10 min–24 h. `--degraded-flag` must be the contract path.

### Rollback

To go back to the previous verified copy:

```sh
launchctl bootout gui/$(id -u)/works.relux.sysadmin.host-watch
# point ProgramArguments[0] back to the previous host-watch-<sum> copy, then
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/works.relux.sysadmin.host-watch.plist
```

To disable the first installation completely:

```sh
launchctl bootout gui/$(id -u)/works.relux.sysadmin.host-watch
rm ~/Library/LaunchAgents/works.relux.sysadmin.host-watch.plist
```

If the exec-degraded flag exists at that moment, check the host first with `/bin/launchctl print system/com.apple.security.syspolicy`. Only the owner removes the flag, and only once syspolicyd is running and a non-Apple binary starts promptly, because once host-watch is stopped nothing republishes it. Heavy lanes stay held while the flag exists.
