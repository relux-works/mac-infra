# TASK-260915-2ny9kd review verdict — CR revision 5

Verdict: **changes_requested** → `to-dev`

repeat-of: revision 4 F1

Reviewed candidate: tree `83a01d57540bc2494b0fd0b069c07de5c0554df7`, patch SHA-256 `b53fea9ad646140c3bd185717a8d6afb56dadb83d20e7159ae25f3c2d85def4c` (matches the handed-off rev5 resource).

## F1 — envelope presence gate is bypassed by lossy typed JSON decoding

`signerclient.readResponse` unmarshals directly into `Response`, where `OK bool` cannot distinguish absent or `null` from explicit `false`, and `Error *Error` cannot distinguish absent from explicit `null`. `checkEnvelope` (`internal/keyvault/signerclient/client.go:193`) therefore does not validate the raw contract-1 envelope shape it claims to validate. The same decode also turns missing or `null` mandatory `error.message` / `error.hint` members into empty strings, which the code accepts after checking only the error code.

Production-entry probe (`signerclient.Start` and `(*Client).Call`) demonstrated:

- startup hello with no `ok` was accepted as a typed `not_found` refusal, not `ErrProtocol`;
- startup hello with `ok:true,result,error:null` was accepted as success and returned a live client;
- startup failure with only `error.code` (no `message` or `hint`) was accepted as a typed refusal;
- mid-stream response with no `ok` was accepted as a typed refusal and left the client live.

This is the repeated envelope-gate class: the 39-row test builds a typed `Response` and serializes it (`client_test.go:223-265`), so it cannot generate absent/null distinctions already erased by that type. Its claimed matrix is 13 of 13 typed shapes but only 0 of 4 newly probed required-member/presence rows; it is not complete against the raw JSON wire contract.

Evidence: `TASK-260915-2ny9kd_review-envelope-presence-probe-rev5.log`. The existing targeted suite still passes (`go test -count=1 ./internal/keyvault/signerclient`, exit 0), confirming the bypass is not covered. The handed-off validation, full-test, race, and mutant logs are complete and green; this finding is contract correctness, not a missing/failed gate run.

Required rework:

1. Preserve raw member presence before typed decode and require `ok` to be present as a JSON boolean; require the selected `result`/`error` member to be present and non-null, and reject an explicit null member on the opposite branch.
2. Validate the documented error object contract (`code`, `message`, `hint`, with their required JSON types/presence) before returning `*Error`.
3. Add a named subprocess-entry regression that writes raw JSON for missing/null `ok`, `error:null`, and missing/null mandatory error members, with nearby valid success/refusal controls. Do not generate these rows by marshaling `Response`.
4. Because this repeats revision 4 F1, ship a narrowing mutant that leaves the raw-envelope gate installed but admits exactly one missing/null-member class; the named production-entry regression must kill it.
5. Record the regression/fix in `LOGBOOK.md` during producer rework; this reviewer kept the repository read-only.

No stop-the-line condition exists; this is ordinary focused rework.
