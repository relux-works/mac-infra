# TASK-260824-2x6qiu recovery validation

## Scope

This is the requested recovery-only producer pass after revision 2 was independently accepted but could not be checkpointed before sibling candidate drift. No redesign or scope expansion was performed.

Current repository identity:

- HEAD: `360cc6d4ee05f4c6309928e1840d65c21b278193`
- HEAD tree: `a779c15decb43ae5c0ba605d2408a92ab0888b50`
- `git diff HEAD --quiet`: exit 0
- `git ls-files --others --exclude-standard`: exit 0, no output
- Expected Change Request repository delta: `empty`

The managed worktree's pre-existing index contains a sibling candidate while the working-tree files restore the checkpointed HEAD tree. It was deliberately left untouched. Change Request construction uses its alternate-index snapshot and therefore observes the current HEAD-equivalent candidate, not the sibling staging state.

## Direct validation rerun

Each gate was run as a standalone command. No gate was piped through `tee` or had its exit status suppressed.

| Gate | Exit | Result |
| --- | ---: | --- |
| `go test -count=1 ./internal/browsersession` | 0 | PASS (`1.400s`) |
| `go test -count=1 ./cmd/mac-chrome-session` | 0 | PASS (`15.807s`) |
| `go test -count=1 ./cmd/mac-safari-session` | 0 | PASS (`1.740s`) |
| `go test -count=1 ./scripts` | 0 | PASS (`1.488s`) |
| `go vet ./internal/browsersession ./cmd/mac-chrome-session ./cmd/mac-safari-session ./scripts` | 0 | PASS |
| `bash -n scripts/setup.sh scripts/deinit.sh` | 0 | PASS |
| `gofmt -l` on heartbeat/CLI/script Go scope followed by an empty-output assertion | 0 / 0 | PASS |
| `go build -o .temp/.../mac-chrome-session ./cmd/mac-chrome-session` | 0 | PASS |
| `go build -o .temp/.../mac-safari-session ./cmd/mac-safari-session` | 0 | PASS |
| `git diff --check HEAD` | 0 | PASS |

## Negative production-entry smoke

Both newly built CLIs were driven through the real `heartbeat start` entry point with otherwise valid target arguments but no TTL/deadline:

| Entry point | Exit | Expected refusal |
| --- | ---: | --- |
| Chrome heartbeat start without `--ttl`/`--deadline` | 2 | `heartbeat requires exactly one of a positive --ttl or --deadline` |
| Safari heartbeat start without `--ttl`/`--deadline` | 2 | `heartbeat requires exactly one of a positive --ttl or --deadline` |

These are expected-red gates and are reported as non-zero refusals, not passes.

The package reruns include the accepted revision's real-clock in-probe and interval-sleep expiry tests, stable installed launcher validation, deadline exclusivity, deadline-free migration, safe restart, cleanup, status/list projection, and Chrome/Safari production CLI lifecycle tests.

## Prior accepted evidence reused

Because the candidate has no repository delta, the invasive installed/setup and TCC designated-requirement smoke was not repeated against the user's installed tools. The previously attached revision-2 reviewer evidence remains tree-applicable and records:

- two distinct launcher binaries producing the same identifier-only designated requirement;
- setup's rejection of the old cdhash-bound requirement;
- installed sandboxed-HOME deadline refusals, expired cleanup, and migration-required status/list behavior;
- ten killed gate mutants, including stable launcher path/mode, pre-probe and sleep-window expiry, Inspect cleanup, migration trigger, strict state load, and both CLI TTL defaults.

No new defect, decision, anomaly, or regression was found in this recovery pass.
