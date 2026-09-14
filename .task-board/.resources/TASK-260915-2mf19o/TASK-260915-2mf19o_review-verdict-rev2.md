# TASK-260915-2mf19o review verdict — CR revision 2

Verdict: **changes requested** → `to-dev`

repeat-of: CR revision 1 F3

Reviewed frozen candidate: base `f9ec756b123ea66a02545369ed007d9ddd8c5540`, candidate tree `68764d6e3536e360b4e463ca14d1af41d9fac9df`, repository delta `present`. All 17 changed worktree paths matched the candidate archive byte-for-byte.

## Findings

### F6 — High — rev1 F3 usage-error class remains bypassable

`run()` dispatches `version` directly at `cmd/mac-keyvault/main.go:215` and ignores `rest`. Consequently `--json version extra` and `--json version --bogus` return a successful version envelope with exit 0 instead of the required usage envelope with exit 2. This is a **bypass path around the check**: the common flag/usage machinery is present but this named production command never invokes it.

`collectMeta` at `cmd/mac-keyvault/main.go:409` decodes one JSON value but never requires EOF. An input file containing `{"owner":"a"} {"ignored":true}` is accepted, creates a key, and persists only the first object. This is the same repeated F3 class and additionally violates the no-backend-call side of a malformed usage refusal.

Scratch production-entry regressions `TestReviewerVersionRejectsExtraInput` and `TestReviewerMetaJSONRejectsTrailingDocument` both fail against the frozen candidate; the latter observed `exit=0` and `backend.touched=true`.

Required rework for this repeated class: add named `run(...)` regressions for version extra positional/unknown flag and a trailing `--meta-json` document, asserting parseable error envelope, empty stderr, exit 2, and zero backend calls. Add narrowing mutants that preserve the common JSON emitter while admitting only the version bypass, and preserve JSON decoding while admitting a second/trailing document; both named regressions must kill them.

### F7 — Medium — the 80-character title limit is implemented as 80 bytes

The model specifies `title ≤ 80 chars`, but `ValidateNew` uses `len(rec.Title)` at `internal/keyvault/record.go:254`. An exactly 80-character Armenian title is rejected as “160 characters”. Scratch regression `TestReviewerTitleCharacterBound` fails on that positive boundary.

Use a Unicode character/code-point count consistently with the normative bound. Add positive 80-character and negative 81-character production-entry controls plus a narrowing mutant that restores the byte-count behavior.

### F8 — Medium — rotate reproduces key-inapplicable issuer metadata

Model v2 requires `issuer: null` for a key. `Manager.Rotate` calls `ValidateNew` at `internal/keyvault/keyvault.go:453`, but `ValidateNew` never validates `Issuer`; a schema-2 key record carrying a forged non-null issuer is accepted and copied into the new generation. Scratch regression `TestReviewerRotateRejectsKeyIssuerMetadata` observed a successful rotate.

Validate the kind-specific issuer invariant before creation and reproduction. Add a positive key/null-issuer control, a negative stored schema-2 key/non-null-issuer rotate test with zero create calls, and a narrowing mutant that admits one non-null issuer shape.

## AC and evidence assessment

Reviewer-measured explicit AC coverage is **12 of 13 rows satisfied**; the “every usage error in `--json` mode” row remains unsatisfied. F1, F2, F4 and F5 were attacked and passed: foreign raw/full labels stop before the backend; the lock spans list-through-create and the positive no-lock race admits both creates; unknown rotate store/schema/label metadata refuses; both private export APIs return `-25316` with zero bytes and the private authorization ACL set resolves to only the calling binary. The producer’s 24-mutant log is complete, but its F3 table does not cover the surviving `version` or trailing-document bypasses.

Validation on the exact candidate: reviewer reran `go test -count=1 ./cmd/mac-keyvault ./internal/keyvault` (pass), `go vet ./...` (pass), `go build ./...` (pass), `gofmt -l cmd/mac-keyvault internal/keyvault` (clean), and exact CR `git diff --check` (pass). The producer’s complete exact-candidate `go test -count=1 ./...` log was reused. Reviewer scratch probes ran in an archive of candidate tree `68764d6…`; they do not modify the review worktree.

No external or human-only blocker exists. This is ordinary implementation/test rework.
