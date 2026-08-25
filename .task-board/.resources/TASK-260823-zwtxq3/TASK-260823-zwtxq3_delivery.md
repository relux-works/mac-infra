# TASK-260823-zwtxq3 developer evidence

## Implementation

- Added `internal/browsersession` as the shared policy/runtime layer for Chrome and Safari targets, atomic origin guards, secret guards, URL/header sanitization, typed refusals, and named heartbeat lifecycle.
- Added the guarded `mac-chrome-session` CLI with exact Chrome window/tab targeting, explicit `focus`/`close`, script/file parity, and shared Chrome/Safari heartbeat commands.
- Made Safari page-context operations exact-window/current-tab with mandatory origins and no front-document fallback. Added explicit handoff focus and shared secret/sanitization policy.
- Added content-addressed heartbeat executable pinning, private state/logs, fail-closed drift handling, bounded status states, safe GC, and setup/deinit integration.
- Updated README, mac-infra skill references, and LOGBOOK. The repeated-element extractor remains outside this change.

## Negative evidence matrix

| Gate | Production entry exercised | Evidence |
| --- | --- | --- |
| N1/N2 secret guard | `run()` in both browser CLIs | script and file inputs refuse every required token before driver execution |
| N3/N4/N6 origin guard | `chromectl.Session.RunJavaScriptResult`, `safarictl.Session.RunJavaScript` | typed mismatch, one-call atomic wrapper, and malformed/empty/sentinel-free response refusal |
| N5 required Safari origin | `run()` and heartbeat argument parsing | Safari run-js and heartbeat reject missing origin before automation |
| N7 focus | generated driver sources | every silent source rejects activation/frontmost/index/active-tab/System Events tokens; only explicit focus sources contain activation |
| N8/N9 retargeting | both public driver methods | missing Chrome tab is typed target-missing with no active-tab fallback; Safari current-tab origin drift refuses before payload |
| N10/N11/N12 heartbeat validation | `HeartbeatManager.Start`/`NewConfig`/plist render | temporary executable paths, unsafe names, traversal, overlong names, and sub-15s intervals fail closed |
| N13/N14 heartbeat privacy/drift | `HeartbeatManager.Run` | mode 0600 JSONL contains only bounded fields; mismatch logs refused and dispatches no payload evidence |
| N15 deinit | `scripts/deinit.sh` subprocess test | managed services, plists, state, logs, pinned copies, and installed test CLI are removed in safe order |
| N16 sanitization | public list/snapshot/fetch decode paths | sensitive query values, userinfo, fragments, and headers are redacted/dropped on output paths |

## Standalone validation results

| Command | Exit | Artifact |
| --- | ---: | --- |
| `gofmt -l .` plus empty-output assertion | 0 / 0 | `gofmt-list-02.log` |
| `go test -count=1 ./...` | 0 | `go-test-02.log` |
| `go vet ./...` | 0 | `go-vet-02.log` |
| `go build ./...` | 0 | `go-build-02.log` |
| `bash -n scripts/setup.sh scripts/deinit.sh` | 0 | `bash-n-02.log` |
| `git diff --check` after docs | 0 | `git-diff-check-03.log` |
| `scripts/setup.sh` after the last change | 0 | `setup-install-08.log` |
| installed skill vs source diff | 0, empty | `installed-skill-diff-03.log` |

## Live evidence and stop-line constraint

- Installed Chrome list, guarded direct Chrome/Safari reads, deliberate wrong-origin refusals, and the obvious secret-read refusal ran without browser focus changes. Raw topology and results remain in task-scoped mode-0600 files and are not attached.
- Chrome and Safari heartbeat preflight calls passed. Two named LaunchAgents were loaded simultaneously with a content-addressed executable and no temporary path.
- The first background page-context calls did not return. Chrome produced a bounded `error/timeout`; Safari remained pending until cleanup. A separate launchd diagnostic proved browser metadata Apple Events succeeds with exit 0 while `execute JavaScript` waits. The same exact-target page-context calls succeed from the installed interactive CLI.
- This isolates macOS Automation consent for the newly pinned background executable as the remaining human-only boundary. A foreground proxy, UI-scripted consent click, non-persistent daemon, or false `running` status would violate the contract. Code now reports a loaded job with no trustworthy outcome as `unavailable`.
- Both throwaway heartbeat jobs and diagnostics were stopped. No managed heartbeat plist, state file, or pinned executable remains.
- The legacy FNS LaunchAgent and the existing T-Bank heartbeat+extractor watcher are alive. FNS was deliberately not migrated because the replacement had no successful background outcome. The T-Bank extractor was never modified.

## Required human input and continuation

Approve macOS Automation access for the newly managed `mac-browser-session-*` background executable to control Google Chrome and Safari when the system prompts. After approval, rerun the two-heartbeat concurrency/drift protocol and then migrate FNS only after three successful overlap intervals.

FNS rollback remains available without deleting the legacy binary:

```bash
launchctl submit -l com.relux.fns-chrome-heartbeat -- /Users/alexis/src/casual-talks/.temp/fns-ip-close/chrome-activity-heartbeat -window-id 704793720 -tab-id 704793726 -interval 45s -log /Users/alexis/src/casual-talks/.temp/fns-ip-close/chrome-heartbeat.log
```

## Continuation evidence — actionable TCC identity

The initial consent diagnosis was incomplete. Unified TCC logs proved that the
raw Go linker signature caused `TCCCreateDesignatedRequirementIdentity...` to
emit macOS security error `-67062`; the prompt could not be retained as a
usable Automation identity. The implementation now:

- applies a complete ad-hoc signature with identifier
  `works.relux.mac-infra.browser-session` during setup;
- verifies cleanly with `codesign --verify --strict` and satisfies its
  designated requirement;
- waits for the first outcome from the actual LaunchAgent process before
  `heartbeat start` succeeds;
- bootouts and removes managed artifacts when that background preflight
  refuses, errors, or times out.

A launchd probe of the newly signed binary was attributed by TCC to
`works.relux.mac-infra.browser-session`, and designated-identity creation
returned without `-67062`. The remaining live boundary is now only the genuine
macOS Automation approval. A guarded direct probe while that prompt remained
unanswered exited `1` with AppleEvent error `-1712`; no browser was focused.

Additional standalone gates after this correction:

| Command | Exit | Artifact |
| --- | ---: | --- |
| `gofmt -l .` plus empty-output assertion | 0 / 0 | `gofmt-list-03.log` |
| `go test -count=1 ./...` | 0 | `go-test-03.log` |
| `go vet ./...` | 0 | `go-vet-03.log` |
| `go build ./...` | 0 | `go-build-03.log` |
| `bash -n scripts/setup.sh scripts/deinit.sh` | 0 | `bash-n-03.log` |
| `git diff --check` | 0 | `git-diff-check-04.log` |
| `scripts/setup.sh` with signed current source | 0 | `setup-signed-02.log` |
| `codesign --verify --strict --verbose=2 bin/mac-chrome-session` | 0 | `codesign-verify-02.log` |
| installed skill vs source diff | 0, empty | `installed-skill-diff-05.log` |
| frontmost application before/after signed consent probe | identical, assertion exit 0 | private task-scoped files |

Private TCC logs remain task-scoped and are not attached because they contain
process paths and runtime identifiers. The board artifact records only the
bounded finding above.

## Third consent checkpoint

The signed read-only diagnostic remained loaded with two runs, `last exit code
= 1`, and a replacement process still waiting in Apple Events. This confirms
that Automation consent was not granted between continuation checkpoints. The
diagnostic was booted out successfully; a subsequent exact-label read returned
launchctl exit `113` (`service not found`).

The preservation boundary still holds after cleanup: the legacy FNS
`com.relux.fns-chrome-heartbeat` service is loaded and running, and the existing
T-Bank watcher process is present. Neither was stopped, replaced, or modified.
No supported heartbeat remains installed from the unsuccessful smoke.

This is the third consecutive goal turn with the same external blocker. The
task remains blocked on one precise human action: approve macOS Automation for
the signed `works.relux.mac-infra.browser-session` runtime to control Google
Chrome and Safari. Until that happens, concurrency/drift evidence and the safe
FNS overlap migration cannot truthfully be produced.
