# BUG-260915-7elb3o review verdict — CR revision 1

## Verdict

**Changes requested** (`to-dev`).

- `repeat-of: none`
- Change Request: `CR-BUG-260915-7elb3o-1`, revision `1`
- Base OID: `0432f74c153b2bffc7ffa9cca95b50cfad8899d3`
- Candidate tree OID: `8ea971a06e7a237654b652577ba52e5a4e567299`
- Patch SHA-256 verified: `a3478d16ed45a6af25b91c6e8eceb780e4fa75d050fcbf8d0267d7cc4ae3b95c`
- Repository delta: present; candidate worktree recomputed to the exact candidate tree before and after review probes.

## Finding F1 — non-PII values are corrupted by field-name classification

Severity: blocking acceptance-criteria failure.

Shape: positive-path-only evidence / missing neighboring non-PII control.

The public `q` production entry changes ordinary values solely because their public field names look sensitive. A browser record containing:

```json
{"id":"p-1","name":"Desk lamp","addressType":"shipping","author":"OpenAI"}
```

successfully renders and persists:

```json
{"addressType":"[ADDRESS_1]","author":"[FULL_NAME_2]","id":"p-1","name":"[FULL_NAME_1]"}
```

This violates the explicit acceptance criterion that non-PII values remain unchanged and contradicts the new README/reference claim.

Production path: `run -> runQuery -> Facade.Query -> Facade.list` at `internal/browserfacade/facade.go:358` calls `docsanitize.SanitizeRecords`; `internal/docsanitize/sanitize.go:107-109` replaces an entire value whenever `classifySensitiveHeader` returns a category. The overbroad classifications are `strings.Contains(..., "address")` at line 466 and exact generic `name` / `author` classifications at line 469. No value-level PII predicate protects these branches.

Reproduction evidence:

- Private fixture: `.temp/BUG-260915-7elb3o/reviewer-probe/adapter.json`
- Public stdout: `.temp/BUG-260915-7elb3o/reviewer-probe/non-pii.stdout`
- Persisted cache under the private probe HOME contains the same corrupted placeholders.
- Fixture directories/files/executables were restricted to `0700`/`0600`/`0700` per the operator directive.

Required rework:

1. Preserve non-PII values for ambiguous public fields such as product `name`, categorical `addressType`, and organization/application `author`; field-name heuristics must not automatically replace arbitrary values wholesale.
2. Add a named production-entry regression test, e.g. `TestRunQProductionEntryPreservesNonPIIValuesInAmbiguousFields`, covering JSON and compact stdout plus cache and grep, with a nearby positive PII control so rejecting/sanitizing nothing cannot pass.
3. Add a bounded mutant that restores one overbroad generic-field classification and prove the named regression test fails uncached; restore the candidate byte-for-byte afterward.
4. Correct the README, browser-site facade reference, implementation evidence, and LOGBOOK claim after the behavior is fixed.

## AC coverage assessment

Reviewer assessment: **6 of 7 rows satisfied; 1 of 7 failed**. Producer evidence names production tests for all seven rows, but row 3 (“field names and ordinary values remain unchanged”) tests only `id`, `title`, and `price`. The neighboring ambiguous-field control above defeats that claim. The remaining existing focused and selected adversarial tests passed on the exact candidate.

## Validation performed by reviewer

- `go test -count=1 ./internal/docsanitize ./internal/browserfacade ./cmd/mac-browser-site` — exit 0.
- Selected production tests for PII stdout/cache/grep, malformed-record atomic refusal, raw-PII cache refusal, and secret-response atomic refusal — exit 0.
- Independent public-CLI neighboring probe — command exited 0 but produced forbidden value corruption, therefore the contract assertion failed.
- `git diff --check <base> <candidate>` — exit 0.
- Candidate snapshot recomputation before and after probes — exact tree `8ea971a06e7a237654b652577ba52e5a4e567299`.

No product code was modified by the reviewer. The `logbook` workflow was inspected because this is a significant regression, but reviewer read-only constraints prohibit adding a candidate `LOGBOOK.md` entry; the producer must update it during rework.
