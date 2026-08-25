# TASK-260823-17qhsl — Architecture-Driven Boundary Validation

Date: 2026-08-24 MSK  
Run: `RUN-260823-7f0b72`  
Goal checkpoint: `GOAL-260823-4cf037` revision 1  
Resolved scope: `TASK-260823-17qhsl`  
Review policy: `required`

## Implemented Migration

- `internal/browserfacade.EnforceOutbound` remains the one exported outbound
  decision owner and retains the single `clean | redacted | refused | unknown`
  state vocabulary. Refused and unknown decisions carry no inspected value.
- The owner now uses one bounded normalization queue for literal, percent,
  nested, JSON-escaped, backslash-escaped, case-varied, and malformed forms.
  Normalization is capped at depth 4, 16 derived variants, and bounded bytes;
  exhaustion or ambiguity becomes `unknown`.
- One normalized sensitive-name policy serves adapter fields, JSON keys,
  assignments, and URL query names. It covers cookies, local/session storage,
  session id/state, IndexedDB/credential sources, authorization, API/signing
  keys, secrets, and token families.
- JSON keys and scalar strings are walked before lossy decode. Duplicate raw or
  normalization-equivalent keys become refusal/unknown. Adapter JSON now uses
  this same pre-decode boundary, in addition to extractor, advance, mutation,
  cache, and renderer data.
- Browser process stdout/stderr is inspected only in memory for boundary class,
  discarded, and represented publicly by `TransportFailure` with a generic
  message and stable `TRANSPORT_FAILED` kind. Clean-looking raw process detail
  has no output path.
- Descriptor-rooted no-follow cache traversal, canonical JSONL rendering,
  final buffered `WriteOutbound`, tri-state pagination, deterministic extraction,
  exact target/origin guards, q/grep/m separation, and mutation preview/confirm
  contracts remain unchanged.

## Red-to-Green Production Evidence

Every command below ran directly as a standalone process without `tee`.

| Command | Exit | Evidence |
| --- | ---: | --- |
| `go test -count=1 ./internal/browserfacade ./cmd/mac-browser-site` after adding cookie/session/storage, escaped-error, and generic-error tests but before production changes | 1 | Expected red: browser secret URL values reached q stdout/cache, escaped errors reached stderr, and clean raw process detail was forwarded. |
| Same focused command after the central migration | 0 | q/schema/cache/render/error production paths pass. |
| Adapter duplicate/escaped-metadata test before `DecodeAdapter` enforcement | 1 | Expected red: duplicate adapter keys survived lossy decode. |
| Same adapter test after pre-decode enforcement | 0 | Duplicate keys are explicit unknown and escaped sensitive metadata is refused. |
| Canonical redacted cache grep test before the JSON-structural fix | 1 | Expected red: a valid multi-redacted cache record became unknown in JSON grep rendering. |
| Same test after the JSON-structural fix | 0 | Canonical redacted q cache is searchable in compact and JSON modes. |

The canonical-cache regression was discovered by the first freshly installed
safe grep smoke, whose CLI exit was 1. It was not treated as success. The test
was added, the structural JSON path was corrected, all source gates were rerun,
the binary was reinstalled, and the final installed q and grep exits were both
0. One earlier installed nested-attack wrapper also exited 1 because zsh reserves
the variable name `status`; the underlying CLI was rerun using `cli_exit`, and
both compact and JSON attack commands truthfully exited 1 with the expected
refusal and absence assertions.

## Narrowing Mutants

Each mutant used a task-scoped byte copy, `-count=1`, and a named production
entry test. The source was restored from the copy and verified with `cmp` and
SHA-256 before continuing.

| Narrowing mutant | Named production test | Mutant test exit | Meaning |
| --- | --- | ---: | --- |
| Remove only cookie/session/storage families from the central name table | `TestRunQProductionEntryGuardsCanonicalBrowserSecretNamesAcrossFormats` | 1 | Compact/JSON q and schema tests expose the narrowed class. |
| Remove only backslash-variant generation | `.../schema-escaped-session-*` subtests of the same production test | 1 | Escaped schema metadata reaches the installed rendering path when normalization is narrowed. |
| Reintroduce raw transport detail instead of `TransportFailure` | `TestRunQProductionEntryWithholdsEscapedTransportErrorsAcrossFormats` | 1 | Clean raw stderr escapes and the stable typed error contract changes. |

Existing production tests also narrow the central credential grammar,
duplicate-key evidence validation, renderer `WriteOutbound`, mutation dispatch
guards, pagination unknown branches, and descriptor-rooted cache traversal.

## Final Source Gates

| Command | Exit | Result |
| --- | ---: | --- |
| `gofmt -l cmd internal scripts` | 0 | Empty output. |
| `go test -count=1 ./...` | 0 | Full uncached module passes, including deterministic extractor and transport tests. |
| `go vet ./...` | 0 | Empty output. |
| `go build ./...` | 0 | Every command compiles. |
| `go test -count=1 -cover ./internal/browserfacade ./cmd/mac-browser-site` | 0 | 81.0% / 88.7% statement coverage. |
| `git diff --check` | 0 | Empty output. |
| `./scripts/setup.sh` after the final source change | 0 | Tests/build/sign/install and skill sync passed; privileged daemon untouched. |
| `task-board validate` | 0 | Board valid. |

## Final Installed Production Matrix

The final matrix ran `/Users/alexis/.local/bin/mac-browser-site` after the last
successful setup. Synthetic values are intentionally omitted. Every rejected
case asserts absence from stdout, stderr, task cache, and—where applicable—the
external physical path.

| Installed entry | Format | CLI exit | Result |
| --- | --- | ---: | --- |
| q list with cookie/session/storage query names | compact / JSON | 0 / 0 | Values redacted; source values absent from output and canonical cache. |
| grep over the resulting canonical cache | compact / JSON | 0 / 0 | Redacted record found without browser transport. |
| q schema with backslash-escaped session URL | JSON (compact also source-tested and previously installed-tested) | 2 | `SENSITIVE_RESPONSE_REFUSED`; metadata absent. |
| q transport failure with escaped callback URL | JSON | 1 | `TRANSPORT_FAILED`; raw stdout/stderr absent. |
| q nested URL in percent-encoded query name | compact | 1 | `SENSITIVE_RESPONSE_REFUSED`; no cache. |
| q `sk-proj-*` credential family | compact | 1 | `SENSITIVE_RESPONSE_REFUSED`; no cache. |
| q ambiguous opaque credential candidate | compact | 1 | `SENSITIVE_RESPONSE_UNKNOWN`; no cache. |
| q duplicate extractor item keys | JSON | 1 | `SENSITIVE_RESPONSE_REFUSED`; no record/cache evidence. |
| q duplicate pagination `advanced` evidence | JSON | 1 | `SENSITIVE_RESPONSE_UNKNOWN`; no guessed `hasMore`. |
| m duplicate `applied` evidence | JSON | 1 | `SENSITIVE_RESPONSE_UNKNOWN`; no success attestation. |
| m without confirmation | compact | 1 | `CONFIRM_REQUIRED`; no transport dispatch. |
| m `--dry-run` | compact | 0 | Preview only; no transport dispatch. |
| grep duplicate-key cache | JSON | 1 | `SENSITIVE_RESPONSE_REFUSED`; neither shadow value rendered. |
| grep with symlinked `mac-infra` ancestor | compact | 1 | `CACHE_SCOPE_REFUSED`; external record not rendered and external file preserved. |

Source tests exercise every attack in both JSON and compact formats where the
entry supports them. Earlier post-install runs in this same lifecycle also
exercised schema, escaped errors, nested URLs, opaque tokens, and duplicate
extractor entries in both formats before the final canonical-cache-only source
adjustment; the final reinstall matrix above reran every security class affected
by the final binary.

## Source / Install Parity

- Installed symlink:
  `/Users/alexis/.local/bin/mac-browser-site -> /Users/alexis/src/mac-infra/.temp/STORY-260615-3izx6l/worktree/bin/mac-browser-site`.
- Final source build and installed binary SHA-256:
  `d56e9342779b6c4aad3257453a8f1377371845ffd4126e5efb4997f687387370`.
- Source and installed `SKILL.md` compare equal: exit 0.
- Source and installed `browser-site-facade.md` compare equal: exit 0.

## Preserved Acceptance Evidence

- q projection, batching, schema introspection, compact output, and bounded
  pagination remain production-covered.
- Only observed extra records prove `hasMore:true`; only complete `none` or
  explicit `advanced:false` proves false; duplicates, bounds, and partial reads
  stay unknown/failure.
- grep is browser-free, cache-scoped, descriptor-rooted, no-follow, bounded, and
  canonical.
- m is adapter-declared, whole-batch validated, previewable, and confirm-only.
- Deterministic template/predicate extraction and Chrome/Safari exact
  target/origin guards remain green in the full suite.
- Representative output evidence remains 1,789 bytes / approximately 448
  tokens raw versus 288 bytes / approximately 72 tokens compact: -83.9%.

## Shared-Lane Provenance

The managed Story worktree already contained uncommitted Safari/Chrome session,
extractor, browser-session, lifecycle, README, skill, and LOGBOOK changes before
this run. No reset, checkout, staging, commit, rebase, merge, or discard was
performed. This run changed the task-owned browser facade boundary and tests,
`cmd/mac-browser-site` error projection/tests, the facade README/reference, and
one concise LOGBOOK entry. Existing sibling Story work remains shared-lane scope
and is not claimed as newly authored here.

No human-only decision or external blocker remains. The candidate is ready for
independent review under the Task's required review policy.
