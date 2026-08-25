# TASK-260615-1tlcpm Recovery Producer Evidence

## Scope

This recovery pass inspected the current checkpointed Safari browser automation
implementation after revision 1 had already received independent acceptance.
The implementation remains present at `HEAD`; the only current candidate delta
is a README correction adding the mandatory `--origin https://example.com` to
the documented `mac-safari-session fetch-file` invocation.

The correction closes accepted-review finding N2: the previous copy/paste
example exited with code 2 because `--origin` is required by the production CLI.
No runtime behavior or architecture was changed in this recovery pass.

## Source Case

The board precondition `mts-harvesting-notes.md` and task notes link the source
case at `/Users/alexis/src/mts/mts-pjsc-regulations`, including
`documents/harvesting-notes.md`. The generalized design retains the proven
Safari page-context flow: authenticated `fetch(..., {credentials: "include"})`,
base64/chunk transfer, local decode, and no cookie/token/header export.

## Gate Evidence

| Gate | Exit | Evidence |
| --- | ---: | --- |
| `go test -count=1 ./cmd/mac-safari-session ./internal/safarictl ./internal/browsersession` | 0 | `go-test-narrow-01.log` |
| `go test -count=1 ./...` | 0 | `go-test-all-01.log` |
| `go build ./...` | 0 | `go-build-all-01.log` |
| `go vet ./...` | 0 | `go-vet-all-01.log` |
| `./scripts/setup.sh` | 0 | `setup-install-01.log` |
| installed `mac-safari-session --help` | 0 | `installed-help-01.log` |
| source/installed skill `diff -qr` | 0 | `installed-skill-diff-01.log` |
| `/usr/bin/codesign --verify --strict bin/mac-safari-session` | 0 | `codesign-safari-01.log` |
| scoped `gofmt -l` empty check | 0 | `gofmt-01.log` |
| `git diff HEAD --check` | 0 | `git-diff-check-01.log` |

The setup run refreshed `~/.agents/skills/mac-infra`, the Codex and Claude skill
symlinks, `~/.local/bin/mac-safari-session`, and the stable signed browser
heartbeat launcher. It did not run privileged daemon installation.

## Negative Evidence

The uncached narrow suite drives the real production entries in
`cmd/mac-safari-session`: `runJavaScript`, `runSnapshot`, and `runFetchFile`.
Named negative coverage refuses secret-bearing JavaScript before Apple Events,
missing exact-window/origin targets, origin drift, missing fetch chunks, and
browser-reported/decoded byte-count mismatch without publishing output or
metadata. `internal/safarictl` also proves no front-document fallback, typed
missing-window/origin drift, and URL/header redaction. These are executable
refusal tests, not positive-path inspection.

## Candidate Delta

`git diff HEAD --stat` reports one insertion in `README.md`. Board-managed index
state contains sibling candidate drift, but every task-relevant working-tree
file except this README line hashes identically to `HEAD`; no sibling scope was
edited or staged.
