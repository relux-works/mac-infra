# TASK-260915-2ny9kd review verdict — CR revision 2

Verdict: **changes_requested** → `to-dev`

repeat-of: CR revision 1 / F2 (F1 below repeats the same incomplete golden-coverage class); F2 below is new (`none`).

Reviewed candidate: base `39131c7b28152fda50ed6224ef7afe566d8829f2`, candidate tree `f64c7ec3b737a54510b33ed8508a5cee8159bfd6`, 62 changed paths, repository delta present. The CR patch SHA-256 is `bfff2cb15979b3f7aacc99001b15d51f88e298918b2f7e84fde9dde46777557b`, matching the handed-off digest. The attached publication validation log is complete and ends with exit 0 for `go test -count=1 ./...`, `go vet ./...`, and `go build ./...`; this review reran the focused signer suites with `-count=1`, built the real binary, and ran focused `go vet`, all exit 0. Green checks do not discharge the findings below.

## F1 — the alleged closed error set omits production responses

Shape: **derive completeness from an independent source** / **blind spot is not an empty set**. This repeats CR revision 1 finding F2.

`signerclient.StreamErrorCodes` says it is the closed set for both the startup hello and request responses, and `TestSignerGoldenCoversStreamErrorCodes` reports 13 of 13 by comparing the golden corpus to that same hand-written list. This is circular: a code omitted from both the list and fixtures is invisible.

The real built binary immediately defeats the claim. These startup calls emitted contract-1 error hellos whose codes are absent from `StreamErrorCodes` and have no byte-exact golden fixture:

- bare `signer` and `signer serve` → `usage`, exit 2;
- raw-label address → `foreign_label`, exit 3;
- `--address Test/x` → `invalid_service`, exit 3;
- `--kind bogus` → `invalid_kind`, exit 3;
- the existing production test also drives negative `--version` → `invalid_purpose`, exit 3.

Therefore the claimed ratio is 13 of at least 18 reachable contract-1 codes, not 13 of 13. Additional post-hello paths are also outside the declared set: a non-empty malformed SPKI reaches `invalid_public_key` from `verify`; a backend sign status `-34018` reaches `missing_entitlement`; an unclassified backend/read error reaches `failure`. The STORY's error contract explicitly includes startup `usage`, `foreign_label`, and `missing_entitlement`; README and SKILL themselves document startup `usage`/`foreign_label` while simultaneously telling consumers that any code outside the 13-item list is a contract break.

Required rework: define the actual contract-1 error surface from the normative signer/error contract, cover every reachable member with a byte-exact golden through its production entry point (startup hello included), and make the docs, client declaration, handlers, and fixtures agree. Because this is the second consecutive finding of this class, revision 3 must carry a named regression that fails when a production-emittable code is absent from the declared/golden set, plus a narrowing mutant for this class. The regression must not derive its expected set solely from `StreamErrorCodes` or solely from the fixture corpus; it must exercise/derive the production surfaces that emit the codes.

## F2 — explicit zero-valued fields bypass op-specific request gates

Shape: **bypass path around the check**.

The wire contract says fields an operation does not use must be absent, and `noParams`/the per-op checks intend to reject them. `Request.AllowHighS` is a plain `bool`, however, so decoding loses presence: explicit `false` becomes indistinguishable from an absent member. The same presence loss applies to explicit empty strings.

Adversarial production probe: the real binary created only the throwaway label `works.relux.mac-keyvault.key.test.review-wire-260915-39c081.v1`, then served these requests:

- `{"id":1,"op":"describe","allow_high_s":false}` → `ok:true`;
- `{"id":2,"op":"pub","allow_high_s":false}` → `ok:true`;
- `{"id":3,"op":"sign",...,"allow_high_s":false}` → `ok:true` and performed a signature.

All three must be `bad_request` because `allow_high_s` belongs only to `verify`; the third demonstrates that the bypass reaches the protected backend, not just a decoder helper. The stream exited 0, and cleanup deleted exactly the throwaway v1 item; a post-delete `describe` returned `not_found`.

Required rework: preserve JSON member presence during request decoding and reject every inapplicable member even when its JSON value is the type's zero value (`false` or `""`). Add a production-entry table covering `describe`, `pub`, and `sign`, assert `bad_request`, unchanged stream usability, and zero backend effects for rejected requests, with nearby valid controls. Add a narrowing mutant that restores the current “explicit false/empty is treated as absent” behavior and prove the named regression kills it.

## AC and evidence summary

- Core behavioral AC rows (hello, describe/pub/sign/verify, malformed/unknown/missing-id/wrong-digest/usage/expiry continuation, EOF, client e2e) have named tests and the focused suite is green.
- Error-code golden coverage is **13 of at least 18 reachable contract-1 codes**, so the “one negative per error code” AC row is not met.
- The request-shape validation gate has an uncovered zero-value bypass through the production server.
- README, SKILL, LOGBOOK, and setup build wiring are present; kvctl nonexistence is correctly stated as a bound.
- No product file was modified by the reviewer. The only Keychain mutation was the task-scoped throwaway test label described above, and it was deleted successfully.

Reviewer evidence logs (local scratch): `.temp/reviewer-startup-code-probe-01.log`, `.temp/reviewer-inapplicable-false-probe-01.jsonl`, `.temp/reviewer-probe-postdelete-01.json`, `.temp/reviewer-focused-tests-01.log`, `.temp/reviewer-focused-vet-01.log`.
