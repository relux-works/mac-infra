# TASK-260615-1tlcpm Review Verdict — ACCEPTED

Reviewer run `RUN-260825-d88f74`. Change Request `CR-TASK-260615-1tlcpm-1` revision 1.
Base `fa43cb316036b0b20bed8906417ab97e408fea4b` -> candidate tree `3a62d7285525fe7f2a5e7b31f2817b80ab36d777`.
Repository delta: present (29 paths, +4541/-291).

## Verdict

Accepted. The three findings from the previous cycle (`RUN-260825-fb1f13`) are
closed in production code, each with a negative test that dies under both a
delete mutant and a narrowing mutant. Every acceptance claim below was
re-derived in this run; nothing was taken from the producer's evidence file.

## Rework Findings Verified Closed

### F1 — fetch-file published truncated bodies as `saved:` (was BLOCKING)

`cmd/mac-safari-session/main.go:381-395` now refuses an empty page-context chunk
and refuses to publish when the decoded length disagrees with Safari's reported
`blob.size`. Output and metadata are written only after the attestation passes.

Mutation evidence (scratch copy of the candidate tree, `go test ./cmd/mac-safari-session -run TestFetchFile -count=1`):

| Mutant | Kind | Result |
| --- | --- | --- |
| delete `chunk == ""` refusal | delete | FAIL `missing-middle-chunk` |
| delete `meta.Bytes` attestation | delete | FAIL `browser-size-mismatch` (exit 0, printed `saved:`) |
| `!=` -> `>` on the byte attestation | **narrow** | FAIL `browser-size-mismatch` (truncation admitted) |
| drop equality, keep `meta.Bytes < 0` | **narrow** | FAIL `browser-size-mismatch` |
| `chunk == ""` -> `chunk == "" && i == 0` | **narrow** | FAIL `missing-middle-chunk` |

The two chunk mutants still die on the byte attestation, so the layers are
independent rather than one gate spelled twice.

### F2 — fetch-file had no behavioral test (was BLOCKING)

`cmd/mac-safari-session/main_test.go:112-217` drives the production `run()`
entry through a fake `osascript` that replays guarded envelopes. Positive case
asserts byte-exact reassembly plus `meta.Bytes == meta.ActualBytesWritten`.
Negative cases assert exit 1, the named refusal on stderr, no `saved:` on
stdout, the pre-existing destination byte-preserved, and no metadata artifact.

### F3 — surviving origin-recheck mutant (was NON-BLOCKING)

`internal/browsersession/session.go:161-163` re-checks origin on the
sentinel-valid `outcome:"ok"` branch, covered by
`TestParseJavaScriptResultRefusesSentinelValidOKWithWrongOrigin`.

| Mutant | Kind | Result |
| --- | --- | --- |
| delete the ok-branch origin re-check | delete | FAIL (previously the whole suite stayed green) |
| replace with `!strings.HasPrefix(origin, "https://")` | **narrow** | FAIL |

## Gates Attacked This Cycle

Safari heartbeat surface, `go test ./cmd/mac-safari-session -run TestSafariHeartbeat -count=1`:

| Mutant | Kind | Killed by |
| --- | --- | --- |
| `*windowID <= 0` -> `< 0` | narrow | `.../missing-window` |
| drop the `https://` origin requirement | narrow | `.../http-origin` |
| drop `OriginOf(o) != o` canonicality | narrow | `.../origin-with-path` |
| `minimumHeartbeatInterval` 15s -> 10s | narrow | `.../short-interval` |
| delete the Chrome-namespace refusal in `requireSafariHeartbeat` | delete | `TestSafariHeartbeatCommandsRefuseChromeNamespaceEntries` |
| delete the Safari filter in `heartbeat list` | delete | same test |

Live negative smoke on the built CLI (argument gates, no browser state created —
`~/Library/Application Support/mac-infra/browser-session/` holds only `bin/` and
`safari-artifacts/`, and no `works.relux.mac-infra-browser-heartbeat.*` plist exists):

- `run-js` without `--origin` or without `--window-id` -> exit 2, no front-document fallback
- `snapshot --window-id 1` without `--origin` -> exit 2
- `fetch-file` without `--origin` -> exit 2; `--page` + `--window-id` together -> exit 2
- `heartbeat start` with both `--ttl` and `--deadline` -> exit 2; past `--deadline` -> exit 2
- `--origin https://user:pw@x.example` and `--origin https://x.example/` -> exit 2
- `--name N` -> exit 2 on the name pattern

Secret boundary: `internal/chromectl/fetch_file.go`, `trusted_input.go`, and
`ax_darwin.m` contain no cookie/storage/authorization handling and no print or
log statements. `RedactSensitiveURL` was rewritten from a parameter-name
denylist to structural redaction; the whole query becomes `[redacted-query]`,
and `data:`/`javascript:`/`view-source:`/`mailto:` become `[redacted-opaque-url]`.

## Independent Verification

Run in the story worktree at candidate content:

- `go build ./...` — exit 0
- `go vet ./...` — exit 0
- `go test ./...` — exit 0, 28 packages
- `go test ./cmd/mac-safari-session ./cmd/mac-chrome-session ./internal/browsersession ./internal/safarictl ./internal/chromectl ./scripts -count=1` — exit 0 (uncached)
- `gofmt -l ./cmd ./internal ./scripts` — empty
- `git diff --check fa43cb3 3a62d72` — exit 0

Install refresh verified without re-running `setup.sh`:

- `agents/skills/mac-infra/SKILL.md` and `references/safari-session.md` are byte-identical to `~/.agents/skills/mac-infra/...`
- `~/.local/bin/mac-safari-session help` lists `open-bg`, `check-js`, `run-js`, `snapshot`, `fetch-file`, `heartbeat`
- the installed binary carries both new refusal strings (`empty chunk %d of %d`, `byte count mismatch`)
- `codesign -d -r-` on it reports `designated => identifier "works.relux.mac-infra.safari-session"`
- the stable launcher exists at `~/Library/Application Support/mac-infra/browser-session/bin/mac-browser-heartbeat-launcher`, mode `0700`

## Acceptance Criteria

| AC | Status |
| --- | --- |
| Source skill documents Safari/browser automation workflow | met — `agents/skills/mac-infra/references/safari-session.md`, `SKILL.md` |
| README lists the new tool and commands | met — tool table row plus the heartbeat and guard sections |
| Reusable CLI for background open/snapshot/run-js/fetch-file | met, plus `heartbeat` and `focus` |
| Tests/build pass or failures recorded | met — all green, re-run uncached |
| setup/install refreshes installed skill/CLI | met — verified against the live install |
| Task resources/notes link the MTS source case | met — task notes name `/Users/alexis/src/mts/mts-pjsc-regulations`; `mts-harvesting-notes.md` is attached |

## Non-Blocking Findings For Follow-Up

**N1 — the library-level Safari page-context guards have no negative test.**
`internal/safarictl/session.go:124-129` refuses `TargetWindowID <= 0` and an
empty `ExpectedOrigin`. Deleting *either* refusal leaves
`./internal/safarictl` and `./cmd/mac-safari-session` fully green. This is not
an exploitable bypass today: all four production callers
(`main.go:217`, `:284`, `:363`, `safariHeartbeatProbe` at `:677`) set both
fields from a CLI-validated `--origin`, and `OpenBackground`'s inferred origin
is overwritten by the flag value before any page-context call. It is the same
shape as F3 — an unproven defense-in-depth layer — and deserves the same fix:
a table test calling `RunJavaScriptResult` with a zero window id and with a
blank expected origin, asserting the typed refusals.

**N2 — README:68 documents a `mac-safari-session fetch-file` invocation that
cannot run.** The Privacy-Safe Document Intake example omits `--origin`;
executing it verbatim gives exit 2 and
`fetch-file requires --resource, --out, and --origin`. This is pre-existing at
the base commit, not a regression introduced by this revision, but it sits in
this task's own documentation deliverable and contradicts README:278, which
states `--origin` is mandatory for `fetch-file`.

**N3 — `--origin https://host:443` is accepted as canonical.** `OriginOf`
preserves an explicit default port, so a heartbeat started that way never
matches the browser's port-normalized `location.origin` and will report
`drifted` forever. It fails safe (drift dispatches nothing) but is a confusing
dead end. Normalizing the default port, or refusing it, would be clearer.

## Scope Note (carried forward, unchanged from the previous cycle)

The candidate tree is a snapshot of the shared `STORY-260615-3izx6l` worktree,
so it carries uncommitted work belonging to sibling board items that were not
handed to this reviewer:

- `internal/chromectl/ax_darwin.{go,m}`, `ax_unsupported.go`, `trusted_input.go`
  and their tests -> `BUG-260825-1wsh7n` (status `to-dev`)
- `internal/chromectl/fetch_file.go`, `cmd/mac-chrome-session` fetch surface ->
  `BUG-260825-2s6iw4` (status `to-dev`)
- `internal/browsersession/heartbeat.go` deadlines/stable launcher and the
  `scripts/setup.sh` codesign requirements -> `TASK-260824-2x6qiu` (status `to-review`)

Those files were checked for build, vet, test, formatting and secret-boundary
regressions and are clean, but they were **not** given a line-by-line review
here. Accepting this Change Request accepts the Safari workflow deliverable for
`TASK-260615-1tlcpm`; it does not close the sibling items, and the orchestrator
should not read a story-branch checkpoint as review of their content.

`LOGBOOK.md` in the working tree carries one entry beyond the candidate tree
(the 0108 codesign entry for `TASK-260824-2x6qiu`), written after the snapshot.
