# BUG-260915-7elb3o review verdict — CR revision 2

## Verdict

Accepted. I reviewed the immutable candidate tree
`b5cffcb701cfe6cd23120783a2e58a3120c1d13d` against base
`0432f74c153b2bffc7ffa9cca95b50cfad8899d3`. The live worktree patch matched
that exact tree before and after review. I made no candidate change.

## Findings

No acceptance-blocking findings.

Revision 1 finding F1 is closed: `name=Desk lamp`,
`addressType=shipping`, and `author=OpenAI` remain unchanged through JSON
stdout, compact stdout, cache, and grep, while adjacent
`fullName=Иванов Иван Иванович` becomes a stable `[FULL_NAME_1]` placeholder.

## Acceptance coverage: 7 of 7 rows driven

| Row | Production call site | Review evidence |
| --- | --- | --- |
| 1. Representative PII is absent from successful list stdout and cache | `run -> runQuery -> Facade.Query -> Facade.list -> docsanitize.SanitizeRecords -> Cache.Write / RenderQuery` | `TestRunQProductionEntryDepersonalizesListStdoutCacheAndGrep`, JSON and compact |
| 2. Repeated PII uses stable result-scoped placeholders | same list path | repeated email and all required category placeholders asserted by the same production test |
| 3. Non-PII values and public structure remain unchanged | same list path, then `runGrep -> Cache.Grep -> RenderGrep` | `TestRunQProductionEntryPreservesNonPIIValuesInAmbiguousFields`, JSON and compact, plus cache and grep |
| 4. Secret-shaped values refuse atomically | `runQuery -> CLITransport.Extract -> decodeOutboundSingleJSON -> EnforceOutbound` | `TestRunQProductionEntryRefusesSecretResponseWithoutOutputOrCacheLeak`; zero stdout/cache asserted |
| 5. Malformed or lossy records fail closed | `runQuery -> Facade.list -> sanitizeItems`; `runGrep -> readBoundedLines -> EnforceOutbound` | malformed structured-value production test; independent invalid-UTF-8 forged-cache production probe |
| 6. Grep consumes only depersonalized cache | `run -> runGrep -> Cache.Grep -> readBoundedLines -> validateCacheRecord` | raw-email committed test plus independent forged legacy raw-full-name cache probe; both refuse with zero stdout |
| 7. Existing query and exact-target transport semantics remain active | `runQuery -> Facade.Query`; `CLITransport.Extract` | existing production/full-suite coverage, including batch/projection and exact-target transport tests |

Stated bound: depersonalization remains the existing `internal/docsanitize`
heuristic for uncommon or context-only PII. Every representative category named
by this task is driven through the public list entry point.

## Independent gate attack

In an isolated archive of the exact candidate tree, I kept the sanitizer gate
present and restored only the overbroad `normalized == "name"` whole-field
classification. Uncached
`TestRunQProductionEntryPreservesNonPIIValuesInAmbiguousFields` failed with exit
1 for the intended reason in both JSON and compact: `Desk lamp` became
`[FULL_NAME_*]`. After byte restoration, the same test passed. The expected-red
transcript is `.temp/BUG-260915-7elb3o-review/mutant-rev2-false-positive.log`.

Independent scratch-only production probes additionally forged a legacy cache
containing a raw full name and a cache line containing invalid UTF-8. Both drove
`runGrep`, refused with the intended fixed error class, emitted no partial
stdout, and did not echo the sensitive/malformed bytes.

## Validation

| Command | Result |
| --- | ---: |
| Targeted production-entry PII, F1, malformed, raw-cache, and secret tests | exit 0 |
| Focused `internal/docsanitize`, `internal/browserfacade`, and `cmd/mac-browser-site` tests | exit 0 |
| Separate focused race tests for all three packages | exit 0 |
| `go test -count=1 ./...` | exit 0 |
| `go vet ./...` | exit 0 |
| `go build ./...` | exit 0 |
| repository-file `gofmt -l` empty assertion | exit 0 |
| exact-candidate `git diff --check` and worktree/candidate binary diff comparison | exit 0 |
| `task-board validate` | exit 0; 77 historical `MISSING_ACTIVITY` diagnostics, ledger mirror `161/161`, zero pending/unowned/journaled failures |

The first combined focused call yielded after reporting the two internal package
passes and before emitting its remaining results; those absent lines were not
counted. Every missing package/race result was rerun in a bounded separate
command and completed with an explicit exit 0.
