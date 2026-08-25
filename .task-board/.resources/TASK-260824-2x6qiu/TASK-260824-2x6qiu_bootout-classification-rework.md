# TASK-260824-2x6qiu — bootout classification rework

## Scope

Closed revision-3 reviewer finding F1 without changing the accepted stable-launcher, deadline, migration, setup, CLI, or documentation contracts.

- `internal/browsersession/heartbeat.go` now retains the `launchctl` verb, exit code, and child output in a typed error.
- Missing `print` requires exit 113 and a `Could not find service "..."` response line.
- Missing `bootout` requires exit 3 and the exact `Boot-out failed: 3: No such process` response line.
- Unstructured `RunCommand` hook failures accept only complete known sentinel messages; arbitrary substrings in rendered command text are not evidence of absence.
- `LOGBOOK.md` records the failed-action-versus-absence root cause and corrected contract.

## Negative evidence

Production call site: `HeartbeatManager.Inspect -> HeartbeatManager.expire -> HeartbeatManager.runLaunchctl -> isMissingLaunchAgent`.

`TestInspectExpiredHeartbeatDoesNotLaunderBootoutFailureWhenIdentityContains113` uses the valid name `hb113`, UID 113, and an executable fake `launchctl` that exits 1 with `Operation not permitted`. It requires `Inspect` to return the genuine cleanup failure rather than `state=expired`.

A narrowing mutant restored only `strings.Contains(err.Error(), "113")`. The named production-entry test failed with exit 1 and showed the false `expired=true` attestation. The exact source was restored byte-for-byte before green validation. Log: `.temp/TASK-260824-2x6qiu/mutant-bare-113-01.log`.

Positive and refusal controls drive the real child-process path:

- bootout exit 3 plus the exact missing-process line remains accepted as an already-absent service;
- print exit 113 plus the actual missing-service line reports `configured-not-loaded`;
- print exit 113 plus `Operation not permitted` reports `unknown`.

## Validation

| Command | Exit | Evidence |
| --- | ---: | --- |
| Real `/bin/launchctl print` against task-scoped absent label | 113 | `Could not find service ...` observed |
| Real `/bin/launchctl bootout` against task-scoped absent label | 3 | `Boot-out failed: 3: No such process` observed |
| `go test -count=1 ./internal/browsersession` | 0 | `go-test-browsersession-06.log` |
| Narrowed bare-`113` mutant, named negative only | 1 (expected red) | `mutant-bare-113-01.log` |
| `go test -count=1 ./cmd/mac-chrome-session` | 0 | `go-test-chrome-cli-02.log` |
| `go test -count=1 ./cmd/mac-safari-session` | 0 | `go-test-safari-cli-02.log` |
| `go test -count=1 ./scripts` | 0 | `go-test-scripts-02.log` |
| `go test -count=1 -p 1 ./...` on final source | 0 | `go-test-full-serial-03.log` |
| `go vet ./...` on final source | 0 | `go-vet-full-02.log` |
| `go build ./...` on final source | 0 | `go-build-full-02.log` |
| `bash -n scripts/setup.sh scripts/deinit.sh` | 0 | `bash-n-lifecycle-02.log` |
| `gofmt -l` scoped check | 0, empty | `gofmt-check-02.log` |
| `git diff --check HEAD` | 0 | `git-diff-check-03.log` |

The first combined CLI/scripts test invocation completed with three `ok` package lines, but its wrapper session id was not retained and therefore its exit code is not claimed. Each package was rerun directly and independently with the exit-0 evidence listed above.

## Installed evidence boundary

The accepted revision-2 setup/signing/install smoke remains attached on the board and the setup, launcher, CLI, and skill files are byte-identical in this rework. I did not reinstall the real user runtime from this shared Story worktree because doing so would publish co-located unaccepted sibling features. Current-source builds and runtime classification tests were rerun directly; the previous installed stable-identity/deadline/migration evidence is reused only for the unchanged install surface.

## Repository delta

`git diff HEAD --name-only` contains exactly:

- `LOGBOOK.md`
- `internal/browsersession/heartbeat.go`
- `internal/browsersession/heartbeat_test.go`

The shared index still contains foreign Story work. No file was staged, committed, reset, or restored from Git in this run.
