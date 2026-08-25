# BUG-260825-2pn2en — developer outcome

## Outcome

- Added optional `mac-chrome-session run-js --out PATH` for both `--script` and `--file`.
- The production entry point preflights a same-directory temporary file before browser dispatch, writes the guarded result, and atomically renames it to the requested path with mode `0600`.
- Successful artifact output writes only `out: PATH` to stdout; page content is not duplicated.
- Missing-value and blank paths return exit 2 before dispatch. Invalid or unwritable preflight paths return exit 1 before dispatch. A publish failure returns exit 1 without falling back to page content on stdout.
- Existing exact window/tab targeting, atomic page-context origin guard, and browser-secret refusal remain in the same `chromectl.Session.RunJavaScript` production path.

## Drift reconciliation

- Before the change, installed `run-js --out` reproduced the reported `flag provided but not defined: -out` refusal with exit 2.
- The attached reproduction's source-only `--script` observation was stale: current source and installed help already exposed `--file`; neither exposed `--out`.
- README, source skill, installed skill, top-level CLI help, and `run-js` flag help now describe the same `--script`/`--file` plus optional atomic `0600 --out` contract.

## Tests and negative evidence

- `go test -count=1 ./cmd/mac-chrome-session ./internal/chromectl` — exit 0.
- `go test -race -count=1 ./cmd/mac-chrome-session ./internal/chromectl` — exit 0.
- `go test -count=1 ./...` — exit 0.
- A narrowing mutant changed both whitespace-aware output-path checks to zero-length-only checks. `go test -count=1 ./cmd/mac-chrome-session -run '^TestRunJSProductionEntryFailsClosedOnMissingInvalidAndUnwritableOutput/blank-path$'` then failed with exit 1 because whitespace reached fake `osascript`. The source was restored byte-for-byte, and the named gate test reran with exit 0.
- Production-entry tests also prove script/file parity, existing-file atomic replacement, missing-parent creation, exact `0600` mode, temp cleanup, no stdout payload duplication, no dispatch on output preflight refusal, no stdout fallback on publish failure, no final artifact on origin refusal, and no artifact/dispatch for blocked browser-secret scripts.

## Build, lint, install, and artifact parity

- `go vet ./...` — exit 0.
- `go build ./...` — exit 0.
- `gofmt -l cmd internal scripts` — exit 0 with no output.
- `git diff --check` — exit 0.
- `./scripts/setup.sh` — exit 0; its full tests, all builds, Chrome ad-hoc signing, binary symlink install, and skill synchronization succeeded.
- Installed top-level `mac-chrome-session help` — exit 0 and advertises atomic `0600 --out PATH`.
- Installed `mac-chrome-session run-js --help` — exit 2 under the command's existing Go flag help convention; it exposes `--script`, `--file`, and `--out` with atomic `0600`/no-stdout wording. This nonzero help behavior is reported as expected, not as a passing gate.
- Installed binary versus source-built signed binary `cmp` — exit 0.
- Source versus installed `SKILL.md` and `references/chrome-session.md` `cmp` checks — exit 0.
- `/usr/bin/codesign --verify --strict bin/mac-chrome-session` — exit 0.
- No-focus installed live smokes against one exact guarded HTTPS Chrome tab passed for both `--script --out` and `--file --out` with exit 0. Each stdout contained only `out: PATH`; both artifacts were mode `0600` and matched the bounded `{origin,readyState}` shape.

## Repository scope

- Changed: `cmd/mac-chrome-session/main.go`, `cmd/mac-chrome-session/main_test.go`, `README.md`, `agents/skills/mac-infra/SKILL.md`, `agents/skills/mac-infra/references/chrome-session.md`, and `LOGBOOK.md`.
- No files were staged or committed. The worktree-local untracked `.task-board/.board-write-ledger.json` was preserved and excluded from the implementation scope.
