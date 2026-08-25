# Heartbeat Hardening Evidence — 2026-08-23

## Root cause

The legacy T-Bank watcher measured shell-process liveness, not successful page
outcomes. Chrome returned Apple Events timeout `-1712`, but the loop retained
the previous success and slept for the next 20-minute interval. The first
unified heartbeat draft also derived one probe timeout from the scheduling
interval, allowing a 20-minute schedule to block one check for 20 minutes.

## Fix

- Each scheduled probe now has at most three 10-second attempts.
- Retry delays are bounded and independent of the scheduling interval.
- Origin mismatch, target missing, secret-guard refusal, and Automation-disabled
  errors fail immediately without retry.
- Status validates the timestamp of the last success. An expired success is
  `unavailable` with `errorKind: stale-outcome`, even when launchd still reports
  a loaded process.
- Status exposes only bounded health metadata: last outcome, timestamp, and
  error kind.

## Validation

- `go test -count=1 ./...`: exit 0.
- `go vet ./...`: exit 0.
- `git diff --check`: exit 0.
- `scripts/setup.sh`: exit 0; signed CLI installed.
- Silent Chrome list: exit 0 in 0.7 seconds.
- Persistent `tbank-support` heartbeat: interval 20 minutes, loaded LaunchAgent,
  first background outcome `ok`, later status `running` with a fresh timestamp.

No browser window was focused and no user tab was closed or navigated.
