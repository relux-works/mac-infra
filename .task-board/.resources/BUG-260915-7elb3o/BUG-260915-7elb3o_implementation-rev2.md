# BUG-260915-7elb3o implementation evidence — revision 2

## Candidate

- Base OID: `0432f74c153b2bffc7ffa9cca95b50cfad8899d3`
- Working-tree patch SHA-256: `2d65a5b44cc11c35ab1221803c1bdcf84bcae4cb1d1ac7575866c0385791f66b`
- Candidate remains uncommitted in the managed Story worktree.
- Revision 2 supersedes revision 1 implementation evidence and addresses reviewer finding F1 only.

## Rework

- `internal/docsanitize.classifySensitiveHeader` no longer treats generic `name`, generic `author`, or every field containing `address` as sufficient evidence to replace the complete value.
- Unambiguous structured headers such as `fullName`, `homeAddress`, and the other declared PII categories retain whole-field depersonalization. Ambiguous fields continue through the shared value-level patterns.
- `TestRunQProductionEntryPreservesNonPIIValuesInAmbiguousFields` drives `run -> runQuery -> Facade.Query -> Facade.list -> docsanitize.SanitizeRecords` for JSON and compact output, cache persistence, and cache-only grep. It preserves `Desk lamp`, `shipping`, and `OpenAI` while an adjacent real full name becomes `[FULL_NAME_1]`.
- `TestSanitizeRecordsPreservesAmbiguousFieldsWithoutValueLevelPII` is the neighboring package control for the reusable structured sanitizer.
- README, `agents/skills/mac-infra/references/browser-site-facade.md`, and LOGBOOK now state the value-evidence rule for ambiguous metadata.

## Production acceptance coverage: 7 of 7 rows driven

| Row | Production call site | Named test |
| --- | --- | --- |
| 1. Representative PII classes absent from successful list stdout and cache | `run -> runQuery -> Facade.Query -> Facade.list -> docsanitize.SanitizeRecords -> Cache.Write/RenderQuery` | `TestRunQProductionEntryDepersonalizesListStdoutCacheAndGrep` |
| 2. Repeated PII receives stable result-scoped placeholders | same list call site | `TestRunQProductionEntryDepersonalizesListStdoutCacheAndGrep` |
| 3. Field names and non-PII values remain unchanged, including ambiguous metadata | same list call site, then `runGrep -> Cache.Grep` | `TestRunQProductionEntryPreservesNonPIIValuesInAmbiguousFields` (JSON, compact, cache, grep) |
| 4. Secret-shaped values refuse atomically without stdout/cache | `run -> runQuery -> CLITransport.Extract -> decodeOutboundSingleJSON -> EnforceOutbound` | `TestRunQProductionEntryRefusesSecretResponseWithoutOutputOrCacheLeak` |
| 5. Malformed or unsafe records fail closed | `run -> runQuery -> Facade.list -> sanitizeItems/docsanitize.SanitizeRecords` | `TestRunQProductionEntryRefusesMalformedRecordWithoutOutputOrCache`; `TestSanitizeRecordsRefusesInvalidUTF8WithoutPartialResult` |
| 6. Grep consumes only depersonalized cache | `run -> runGrep -> Cache.Grep -> readBoundedLines -> validateCacheRecord` | `TestRunGrepProductionEntryRefusesCacheContainingRawPII`; positive grep paths in both production PII tests |
| 7. Query projection, exact-target transport, field, and pagination semantics remain active | `runQuery -> Facade.Query`; `CLITransport.Extract` | `TestRunQProductionEntrySupportsBatchProjectionAndCompactOutput`; `TestCLITransportUsesChromeExtractorAndExactTargetThenEvaluatesGuardedSource`; full suite |

Stated bound: PII recognition remains heuristic for uncommon or context-only values, consistent with `internal/docsanitize`. Ambiguous metadata is preserved unless the shared value-level patterns identify PII; explicitly personal headers retain structured whole-field handling.

## Narrowing mutant evidence

The revision 2 mutant kept structured classification active but restored exactly one overbroad member, generic `name`. The test was uncached and production-entry based. Source was copied before mutation and restored byte-for-byte afterward; both restored files had SHA-256 `8e6a8d52a4db539cc8b8e753fe77fa808cb3ef0b2c670658e9e15dbff03f422e`.

| Mutant | What it narrows the preservation gate to | Named test that fails | Survivor bound |
| --- | --- | --- | --- |
| Restore `normalized == "name"` whole-field classification | Preserves ambiguous `author`/`addressType` but corrupts product `name` without value-level PII | `TestRunQProductionEntryPreservesNonPIIValuesInAmbiguousFields` failed for JSON and compact; exit 1 | Killed; no survivor |

Expected-red evidence: `.temp/BUG-260915-7elb3o/mutant-generic-name-classification-01.log` (exit 1). Restored positive control: `.temp/BUG-260915-7elb3o/ambiguous-field-regression-green-01.log` (exit 0).

## Validation

| Command | Exit | Evidence |
| --- | ---: | --- |
| `go test -count=1 ./internal/docsanitize ./internal/browserfacade ./cmd/mac-browser-site` | 0 | `.temp/BUG-260915-7elb3o/focused-rework-01.log` |
| `go test -race -count=1 ./internal/docsanitize ./internal/browserfacade ./cmd/mac-browser-site` | 0 | `.temp/BUG-260915-7elb3o/race-focused-rework-01.log` |
| `go test -count=1 ./...` (first attempt) | 1 | `.temp/BUG-260915-7elb3o/full-test-rework-01.log`; unrelated 3.03s execution exceeded the 3s `TestSlackReadProductionPathAtResponseCeilingMeetsCostBound` threshold |
| `go test -count=1 ./internal/chromectl -run '^TestSlackReadProductionPathAtResponseCeilingMeetsCostBound$'` | 0 | `.temp/BUG-260915-7elb3o/chromectl-cost-diagnostic-01.log` |
| `go test -count=1 ./...` (diagnostic rerun, unchanged candidate) | 0 | `.temp/BUG-260915-7elb3o/full-test-rework-02.log` |
| `go vet ./...` | 0 | `.temp/BUG-260915-7elb3o/vet-rework-01.log` |
| `go build ./...` | 0 | `.temp/BUG-260915-7elb3o/build-rework-01.log` |
| `xargs gofmt -l < .temp/BUG-260915-7elb3o/go-files-rework-01.txt` and empty-output assertion | 0 / 0 | `.temp/BUG-260915-7elb3o/gofmt-check-rework-01.log` |
| `git diff --check` | 0 | `.temp/BUG-260915-7elb3o/diff-check-rework-01.log` |
| `task-board validate` before and after evidence/checklist mutations | 0 / 0 | `.temp/BUG-260915-7elb3o/task-board-validate-rework-01.log`; `.temp/BUG-260915-7elb3o/task-board-validate-rework-02.log` |
