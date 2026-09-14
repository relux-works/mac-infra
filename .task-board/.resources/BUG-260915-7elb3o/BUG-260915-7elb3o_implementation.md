# BUG-260915-7elb3o implementation evidence

## Candidate

- Base: `0432f74c153b2bffc7ffa9cca95b50cfad8899d3`
- Story branch: `task-board/story/STORY-260803-5uvf7l`
- Delivery state: uncommitted working-tree candidate, as required for managed Story handoff
- Scope: `internal/docsanitize`, `internal/browserfacade`, `cmd/mac-browser-site` tests, README, browser-site facade skill reference, and LOGBOOK

## Implementation

- Added `docsanitize.SanitizeRecords`, which reuses the existing PII patterns and one shared redactor across a complete record result. It preserves field names, record order, and non-PII bytes; camel-case structured field names are classified without duplicating PII regexes.
- `browserfacade.Facade.list` invokes the structured sanitizer after complete projection/windowing and before `Cache.Write` or public rendering.
- `Cache.Write` and `Cache.Grep` validate that records are already depersonalized; grep refuses raw-PII cache rather than repairing it.
- The pre-existing outbound secret boundary remains earlier and independent. Canonical docsanitize placeholders are admitted explicitly; malformed bracket forms remain fail-closed.
- Invalid UTF-8, non-text projected values, raw PII cache, and secret-bearing responses produce no partial stdout or cache write.

## Production acceptance coverage: 7 of 7 rows driven

| Row | Production call site | Named test |
| --- | --- | --- |
| 1. Required representative PII classes absent from successful list stdout and cache | `run -> runQuery -> Facade.Query -> Facade.list -> docsanitize.SanitizeRecords -> Cache.Write/RenderQuery` | `TestRunQProductionEntryDepersonalizesListStdoutCacheAndGrep` (JSON and compact) |
| 2. Repeated values receive stable result-scoped placeholders | same list call site | `TestRunQProductionEntryDepersonalizesListStdoutCacheAndGrep` |
| 3. Field names and ordinary IDs/titles/prices remain unchanged | same list call site | `TestRunQProductionEntryDepersonalizesListStdoutCacheAndGrep`; neighboring `TestRunQProductionEntrySupportsBatchProjectionAndCompactOutput` |
| 4. Secret-shaped values refuse the whole read with no stdout/cache side effect | `run -> runQuery -> CLITransport.Extract -> decodeOutboundSingleJSON -> EnforceOutbound` | `TestRunQProductionEntryRefusesSecretResponseWithoutOutputOrCacheLeak`; existing variant suites |
| 5. Malformed/unsafe records fail closed | `run -> runQuery -> Facade.list -> sanitizeItems`; structured UTF-8 guard in `docsanitize.SanitizeRecords` | `TestRunQProductionEntryRefusesMalformedRecordWithoutOutputOrCache`; `TestSanitizeRecordsRefusesInvalidUTF8WithoutPartialResult` |
| 6. Grep consumes only depersonalized cache and never repairs raw PII | `run -> runGrep -> Cache.Grep -> readBoundedLines -> validateCacheRecord` | `TestRunGrepProductionEntryRefusesCacheContainingRawPII`; positive control in `TestRunQProductionEntryDepersonalizesListStdoutCacheAndGrep` |
| 7. Existing query projection, exact-target transport, field, and pagination semantics remain active | `runQuery -> Facade.Query`; `CLITransport.Extract` | `TestRunQProductionEntrySupportsBatchProjectionAndCompactOutput`; `TestCLITransportUsesChromeExtractorAndExactTargetThenEvaluatesGuardedSource`; full suite |

Bound: depersonalization remains heuristic for uncommon/context-only PII, matching `internal/docsanitize`; this candidate proves every representative class named by the acceptance criteria. Invalid raw UTF-8 is rejected by the pre-lossy outbound transport boundary before structured decode, while the reusable structured entry independently refuses invalid UTF-8.

## Narrowing mutant evidence

Each mutant was run uncached with `-count=1`, failed as expected with real exit code 1, and was restored byte-for-byte before green validation.

| Mutant | What it narrows the gate to | Named test that fails | Survivor bound |
| --- | --- | --- | --- |
| Restore raw `email` after the production `SanitizeRecords` call | PII pass protects every class except email; sanitizer call remains present | `TestRunQProductionEntryDepersonalizesListStdoutCacheAndGrep` | Killed; no survivor |
| Exempt `title` values containing `@` from cache depersonalization mismatch refusal | Cache gate rejects other raw PII but admits raw email | `TestRunGrepProductionEntryRefusesCacheContainingRawPII` | Killed; no survivor |
| Admit every value with `[` prefix instead of exact docsanitize placeholders | Placeholder allow gate accepts malformed bracket-shaped values | `TestEnforceOutboundAdmitsOnlyCanonicalDocumentSanitizerPlaceholders` | Killed; no survivor |

Expected-red logs:

- `.temp/BUG-260915-7elb3o/mutant-email-bypass-01.log` — exit 1
- `.temp/BUG-260915-7elb3o/mutant-cache-email-admission-01.log` — exit 1
- `.temp/BUG-260915-7elb3o/mutant-placeholder-prefix-01.log` — exit 1

No new gate inspects source text; the source-token-preserving obligation is therefore not applicable. The first mutant nevertheless preserves the `SanitizeRecords` call and changes production behavior.

## Validation

| Command | Exit | Evidence |
| --- | ---: | --- |
| `go test -count=1 ./internal/docsanitize ./internal/browserfacade ./cmd/mac-browser-site` | 0 | `.temp/BUG-260915-7elb3o/focused-final-01.log` |
| `go test -race -count=1 ./internal/docsanitize ./internal/browserfacade ./cmd/mac-browser-site` | 0 | `.temp/BUG-260915-7elb3o/race-focused-01.log` |
| `go test -count=1 ./...` | 0 | `.temp/BUG-260915-7elb3o/full-test-01.log` |
| `go vet ./...` | 0 | `.temp/BUG-260915-7elb3o/vet-01.log` |
| `go build ./...` | 0 | `.temp/BUG-260915-7elb3o/build-01.log` |
| `xargs gofmt -l < .temp/BUG-260915-7elb3o/go-files-01.txt` plus empty-output assertion | 0 / 0 | `.temp/BUG-260915-7elb3o/gofmt-check-01.log` (empty) |
| `git diff --check` | 0 | `.temp/BUG-260915-7elb3o/diff-check-01.log` (empty) |
| `task-board validate` | 0 | `.temp/BUG-260915-7elb3o/task-board-validate-01.log` |

The earlier focused candidate run `.temp/BUG-260915-7elb3o/focused-after-01.log` failed with real exit 1 and exposed the `ipAddress` classification/order and canonical-placeholder composition defects; it is diagnostic evidence, not reported as passing. Both defects were corrected before the green runs above.
