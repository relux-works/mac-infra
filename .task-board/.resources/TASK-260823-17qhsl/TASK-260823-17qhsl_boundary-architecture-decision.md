# TASK-260823-17qhsl Boundary Architecture Decision

Date: 2026-08-24

Status: proposed developer contract after CR revision 4; implementation is not part of this solution-architect handoff.

## Decision summary

Retain exactly one public outbound decision owner in `internal/browserfacade`: `EnforceOutbound`. Replace the revision-4 representation-specific checks behind that owner with one bounded normalization pipeline, one normalized sensitive-name policy, and one `clean | redacted | refused | unknown` decision. Every value that may enter the cache or leave through q, grep, m, schema, compact, JSON, or error output must pass this owner after all source-specific data has been converted into a typed boundary subject and before any bytes are written.

The facade will fail closed when it cannot classify a malformed, multiply encoded, or opaque value within fixed bounds. Refused and unknown decisions retain no inspected value. Transport failures will be projected to typed generic errors and will never forward raw browser-process stdout or stderr, even if that text appears clean.

This decision preserves the deterministic extractor/template/predicate contract, the q/grep/m separation, pagination unknown semantics, exact-target/origin transport guards, compact output, and cache-only grep.

## Authoritative requirements and traceability

| ID | Requirement source | Requirement | Decision evidence |
| --- | --- | --- | --- |
| R1 | Task Description and Scope | Token-efficient agent-facing facade over Chrome/Safari site adapters | Existing q/grep/m facade remains; this decision changes only its outbound trust boundary. |
| R2 | Task Acceptance Criteria: q | q uses projection and batching | Query AST, projection, batching, schema, and render contracts remain unchanged. |
| R3 | Task Acceptance Criteria: pagination | Marketplace lists are bounded and compact | Existing `maxPages`, 100-result, 1,000-scan bounds and tri-state `hasMore` remain authoritative. |
| R4 | Task Acceptance Criteria: grep | Full-text search is cache-scoped | Cache reads remain browser-free and descriptor-relative; this decision strengthens physical anchoring and revalidation. |
| R5 | Task Acceptance Criteria: m | Mutations are explicit and guarded | Adapter declaration, whole-batch validation, `--dry-run`, mandatory `--confirm`, and `verification: unknown` remain. |
| R6 | Task Acceptance Criteria: no secret escape | Cookies, storage, authorization material, opaque session state, tokens, and secret-bearing URLs cannot escape | One normalized policy covers names, assignments, URL query names, JSON keys, scalar values, errors, cache, and all renderers. Ambiguity is refused or unknown. |
| R7 | Task Acceptance Criteria: efficiency | Output-size/token comparison is recorded | Existing 1,789-byte raw versus 288-byte compact comparison remains required evidence and is unaffected. |
| R8 | Extractor foundation outcome | Preserve allowlisted sources, one optional predicate, `skip`/`take`, bounded shadow traversal, and field caps | No extractor template, predicate, selector, projection, or bound is redesigned. Raw response validation is inserted before lossy decode. |
| R9 | Rework cycles 1-4 | Close repeated secret variants without per-surface filters | The pipeline and policy below directly cover every reproduced variant and make all surfaces consumers of the same decision. |
| R10 | Browser-session references | Keep Chrome exact window/tab and Safari exact window/current-tab with atomic origin guard; never bypass the page-context blocklist | Transport invocation and target/origin requirements stay unchanged. Constructed JavaScript access to browser secrets remains prohibited. |

## Review-history diagnosis

| Revision | Reproduced gap | Architectural cause |
| --- | --- | --- |
| CR 1 | Schema descriptions, URL keys, and opaque credentials escaped; pagination guessed booleans | Output policy was split by surface; pagination treated a bound or stale read as evidence. |
| CR 2 | Uppercase URL, GitLab token, and duplicate-key cache shadowing escaped | Classification depended on literal spelling and lossy decode; grep rendered unvalidated source bytes. |
| CR 3 | Encoded URL in a query name, `sk-*`, duplicate extractor/advance/mutation evidence, and ancestor symlink escaped | Normalization did not cover names and all representations; evidence and paths were trusted before structural validation. |
| CR 4 | Cookie/session/storage URL names and backslash-escaped transport-error URLs escaped | `safePublicField` and `sensitiveOutboundName` remained different policies; JSON/backslash scalar decoding and safe typed error projection were absent. |

The repeated shape is not a list of unrelated token bugs. It is one decision being made after different lossy transformations by different classifiers. The fix is to normalize structure once, classify once, and make every outbound sink consume the result.

## Threat model

### Protected material

- Browser cookies and cookie headers.
- Local/session storage, IndexedDB-derived state, credential APIs, and opaque browser session state.
- Authorization and proxy-authorization material.
- Access, refresh, identity, API, signing, callback, CSRF, and similar credentials or tokens.
- Secret-bearing URL user-info, fragments, query names, query values, nested URLs, and encoded variants.
- Raw transport stdout/stderr and malformed or ambiguous evidence that could contain any protected material.

### Attacker-controlled inputs

- Adapter names, public field names, mutation descriptions, selectors, and pagination declarations.
- DOM field values and extractor envelopes returned by an authenticated page.
- Pagination advance and mutation evidence returned by page JavaScript.
- Browser transport stdout, stderr, exit behavior, and malformed or partial output.
- Existing cache bytes, duplicate JSON keys, filenames offered through `--file`, and symlinks in cache paths.
- Query projections, predicates, batch syntax, grep patterns, and compact/JSON format selection.
- Literal, case-varied, percent-encoded, nested, JSON-escaped, backslash-escaped, duplicated, and malformed representations.

### Trusted components

- The installed facade binary and its compiled policy.
- The existing Chrome exact-window/exact-tab and Safari exact-window/current-tab atomic origin guards.
- Descriptor-relative filesystem primitives after a trusted physical anchor has been opened.

The page, adapter, browser process output, cache, and human-readable error text are not trusted.

### Explicit non-goals

- Detecting compromise of macOS, the browser binary, or the facade binary itself.
- Defending against a privileged or same-user attacker that can modify the running process memory.
- Reading cookies, storage, credentials, or cursor/session state and then attempting to sanitize them. Those sources remain unsupported and must not be read.
- Bypassing browser-session JavaScript guards through constructed property access.
- Screenshots, clipboard capture, keychain extraction, network interception, or browser UI scripting.
- Proving semantic secrecy of every arbitrary short natural-language string. When an opaque value cannot be distinguished from a credential within the declared policy, the result is `unknown`, not an unsupported claim that it is public.

## Enforceable public contract

| Surface | Contract |
| --- | --- |
| Adapter/schema metadata | Public names and descriptions pass the same normalized policy as live data. Selectors and exact targets remain private and never appear in schema output. |
| Extractor items | Only projected allowlisted fields are accepted. Names and raw scalar values are checked before map decoding; ambiguous or sensitive records fail the entire read before cache creation. |
| Pagination evidence | Only a unique, fully parsed boolean `advanced` value is evidence. Missing, partial, malformed, or duplicate evidence is a typed failure/unknown. Bounds and stale pages remain `hasMore: unknown`. |
| Mutation evidence | Only the declared typed envelope is accepted after duplicate-aware validation. Click dispatch never proves business success; verification remains `unknown` unless the declared contract can prove refusal. |
| Transport errors | Raw stdout/stderr is never projected. Callers receive a stable code and generic message derived from typed process state only. |
| Cache writes | Only canonical projected records with a clean final decision are written, atomically and mode `0600`, under the physical site root. Refused/unknown reads create no cache artifact. |
| Cache reads/grep | Raw JSONL is duplicate-aware validated, decoded, canonicalized, re-enforced, then searched/rendered. Original source bytes are never returned. A malformed or unsanitized cache is a refusal, not an empty result. |
| Compact and JSON output | The complete buffered representation passes `EnforceOutbound` immediately before the first byte is written. No renderer may write incrementally. |
| Cookies/storage/session state | Names, assignments, URL keys, JSON keys, and source provenance are denied by the same canonical name policy. The facade does not read these browser sources. |
| Tokens and authorization | Authorization syntax, recognized credential grammars, sensitive-name contexts, and opaque credential candidates are refused. Ambiguous high-entropy values fail as unknown unless the facade replaces them with a non-reversible safe handle. |
| URLs | Scheme and host matching is case-insensitive. User-info and fragments are removed. Every decoded query name and every duplicate value is classified; sensitive values are redacted only when the transformed URL reaches a stable clean fixed point, otherwise the whole value is refused/unknown. |

The public documentation must say “recognized credential/token material and browser session material are refused; ambiguous opaque values fail closed.” It must not claim that a finite scanner can infer the intent of every arbitrary string.

## Single decision model

`EnforceOutbound` remains the sole exported security decision owner. Internal helpers may parse or normalize, but they must not return a competing allow/refuse result to a surface.

```text
OutboundState = clean | redacted | refused | unknown

OutboundDecision:
  state        OutboundState
  safe_value   bytes only when state is clean or redacted
  reason_code  stable non-sensitive code

BoundarySubject:
  kind         document | scalar | name | url | typed-error
  raw          bounded bytes
  provenance   adapter | extractor | advance | mutation | cache | renderer | transport
```

Rules:

1. `refused` and `unknown` never carry raw input, decoded variants, a URL, or error detail.
2. `redacted` carries only the canonical transformed value and is rescanned to a clean fixed point before release.
3. Surface code may act only on `safe_value`; it may not inspect helper-local parse results to decide that a value is public.
4. A helper failure, recursion/variant budget exhaustion, malformed recognized encoding, or inconsistent representation becomes `unknown`.
5. A sensitive observation in any equivalent representation dominates all clean observations and becomes `refused`.

## Bounded normalization pipeline

The pipeline is a bounded work queue, not a chain of surface regexes.

1. **Envelope bounds.** Reject invalid UTF-8, NUL/control ambiguity, input above the surface cap, transform depth above 4, more than 16 derived variants, or cumulative derived bytes above 4 times the input cap as `unknown`.
2. **Pre-lossy JSON walk.** When input is JSON-shaped, stream tokens before `json.Unmarshal`. Reject malformed JSON, trailing non-whitespace, duplicate raw keys, and duplicate normalized keys. Classify every object key and recursively enqueue every string scalar. Numbers, booleans, and null are structurally accepted but do not bypass surrounding name checks.
3. **Literal scan.** Recognize authorization/cookie header syntax, sensitive assignments, known credential grammars, and opaque credential candidates in the original representation. These are data tables or generic structural rules owned by this package, not surface-specific regexes.
4. **Escape normalization.** Enqueue canonical variants produced by valid JSON string escapes, `\/`, `\\`, and `\uXXXX` sequences. Embedded backslash-escaped URLs are decoded through this stage even when the whole transport error is not a JSON document. A malformed escape adjacent to a URL/secret hint is `unknown`.
5. **Percent normalization.** Decode query/path percent encoding for at most four rounds. Query-name and query-value decoding are distinct; `+` ambiguity outside a parsed query is `unknown`. Enqueue every changed variant. Remaining recognized encoded-secret hints at the bound are `unknown`.
6. **URL parsing.** Locate HTTP(S) candidates case-insensitively in each normalized variant and parse structurally. Classify decoded host, path, every query name, and every duplicate query value. Scan query names and values recursively for nested URLs. Strip user-info and fragments. A sensitive query name causes safe redaction only if every value can be replaced and the canonical URL rescans clean; a secret-bearing/nested name or ambiguous parse refuses the whole scalar.
7. **Canonical name policy.** Normalize names by ASCII case-folding and removing separators (`_`, `-`, `.`, spaces) after bounded decoding. Non-ASCII or malformed encoded security-relevant names are `unknown`. One policy covers fields, JSON keys, assignments, and URL query names. It includes cookie, storage, local/session storage, IndexedDB, authorization/auth, credential, password, secret, token, session/session-id/session-state, CSRF, API/signing/private key, signature/sig, callback code, and state families plus normalized suffix/prefix rules. The current separate `safePublicField`, `sensitiveJSONOutputKey`, and `sensitiveOutboundName` decisions are removed or made thin calls into this one policy.
8. **Fixed-point rescan.** Canonical JSON, redacted URLs, compact output, and JSON output are put through the same queue again. A second transformation, non-idempotent redaction, or remaining unvisited secret-capable encoding is `unknown`.

## Structural provenance and safe projections

- The deterministic extractor continues to read only text and existing non-URL allowlisted attributes. It never gains cookie/storage/credential sources.
- Raw extractor, advance, mutation, and cache bytes are boundary subjects before any map/struct decode that can collapse duplicate keys.
- Cursor pagination stays page-owned. The facade receives only typed `advanced` evidence, never the cursor value.
- Transport errors become `TransportFailure{kind, command, exit_class}`. Raw stdout/stderr may be inspected in memory to choose refused/unknown but is always discarded; it is never used as the human-facing message.
- If a projected opaque identifier triggers the generic ambiguity rule, the only exception is a facade-derived non-reversible handle such as a bounded digest. An adapter cannot declare arbitrary raw text “safe” and bypass the decision.

## Cache physical-scope contract

1. The public CLI accepts no cache root.
2. Open a fixed trusted anchor descriptor and traverse every subsequent path component relative to it with no-follow semantics. Do not resolve a string path and reopen it later.
3. Reject symlinks and non-directories in every facade-owned or attacker-influenced directory component. Open cache files descriptor-relative, require regular files, cap size/records, and never follow a symlink final component.
4. Create directories and temporary files descriptor-relative with private modes; publish by same-directory atomic rename.
5. A custom `Cache.Root` remains an internal/test dependency. It must be anchored with the same rules and must not become a CLI filesystem-root option.
6. A host whose configured cache path legitimately relies on symlinked components is refused. This compatibility cost is accepted because permitting it makes the physical-scope claim unprovable.

## Production enforcement points

| Entry point | Required path through the owner |
| --- | --- |
| `mac-browser-site q ... schema()` | `runQuery -> loadAdapter -> DecodeAdapter/Validate -> schemaResult -> EnforceOutbound -> RenderQuery -> WriteOutbound` |
| `mac-browser-site q ... list()` | `runQuery -> Facade.Query -> CLITransport.Extract -> pre-decode EnforceOutbound -> projection -> cache canonicalization/write -> RenderQuery -> WriteOutbound` |
| `mac-browser-site grep` | `runGrep -> descriptor-rooted Cache.Grep -> pre-decode EnforceOutbound -> canonical search result -> RenderGrep -> WriteOutbound` |
| `mac-browser-site m --dry-run/--confirm` | `runMutation -> Adapter.Validate -> whole-batch validation -> typed evidence pre-decode EnforceOutbound -> RenderMutations -> WriteOutbound`; dry-run does not enter page context |
| Transport failure | `ExecRunner -> typed TransportFailure -> generic coded projection -> WriteOutbound`; raw detail has no output path |
| Direct renderer/library use | `RenderQuery/RenderGrep/RenderMutations -> complete buffer -> WriteOutbound`; tests must prove bypassing earlier checks still cannot write |

No old per-surface sanitizer may remain as an alternative path. Grep cannot return raw cache lines, schema cannot return unchecked adapter descriptions, and `fail` cannot print inspected transport detail.

## Invariants

1. There is one exported outbound owner and one normalized decision vocabulary.
2. No raw external evidence is lossily decoded before duplicate-aware boundary validation.
3. All security-relevant names use one normalized policy.
4. Every representation transform is bounded; exhaustion or ambiguity is unknown.
5. Refused and unknown decisions retain and emit no inspected material.
6. Raw transport stdout/stderr is never a user-facing error payload.
7. Cache search is browser-free, physically rooted, canonical, bounded, and no-follow.
8. Every output is buffered and enforced before its first byte is written.
9. Pagination reports only proven `true`/`false`; all proxy evidence remains unknown.
10. The deterministic extractor/template/predicate contract and exact target/origin guards do not change.
11. q, grep, and m remain separate capabilities; grep cannot open a browser and q cannot accept implicit writes.
12. `--dry-run` never enters page context, and every applied mutation requires `--confirm`.

## Negative-test and narrowing-mutant matrix

Every row must drive the real source-built CLI and a freshly installed CLI. JSON and compact modes are required wherever the entry supports them. Assertions cover nonzero refusal or explicit unknown plus absence from stdout, stderr, cache, and any attacker-selected external physical path.

| Boundary class | Production attack | Narrowing mutant that must fail a named test |
| --- | --- | --- |
| Shared name policy | Cookie, `session_id`, `session-state`, local/session-storage, and mixed-case/separator variants in list URLs, schema descriptions, JSON keys, and assignments | Remove only the cookie/session/storage family from the central name table; q list and schema production tests must fail. |
| Escaped URLs | Secret URL as `https:\/\/`, `https:\\u002f\\u002f`, JSON string scalar, and mixed backslash/percent nesting in transport stderr and schema metadata | Disable only JSON/backslash variant generation; transport-error and schema tests must fail while literal URL tests remain green. |
| Nested/encoded URLs | Secret URL in encoded query name and value, repeated percent encoding, uppercase scheme/host, duplicate sensitive keys | Reduce percent rounds from 4 to 1 or stop scanning decoded names; nested production tests must fail. |
| Credential values | Bearer/JWT, GitHub, GitLab, `sk-proj-*`, `sk-*`, Stripe-style, and an opaque high-entropy candidate | Narrow the central credential grammar to vendor prefixes only; the opaque-candidate test must fail. |
| JSON ambiguity | Duplicate raw and normalization-equivalent keys in extractor items, advance evidence, mutation evidence, cache, and rendered JSON | Check duplicates only for `title`; advance/mutation/cache production tests must fail. |
| Error projection | Browser process emits an otherwise clean secret-bearing URL or token in stdout/stderr and exits nonzero | Reintroduce raw detail into the typed error message; absence assertions must fail. |
| Renderer bypass | Call q/grep/m with an earlier sanitization path deliberately bypassed and sensitive data supplied to renderer input | Remove only `WriteOutbound` from one renderer; its JSON and compact tests must fail. |
| Cache write/read | Duplicate-key JSONL, unsanitized canonical record, malformed line, symlink final file, and symlinked ancestor | Permit symlinks in one intermediate component or render original JSONL; grep production tests must fail. |
| Pagination evidence | Duplicate page, caller/adapter/global bound, partial/malformed extract/advance, explicit `advanced:false`, observed extra record | Change one unknown branch to true/false; tri-state production test must fail. |
| Transport targeting | Wrong Chrome tab/origin and changed Safari current-tab origin | Remove the origin argument or exact Chrome tab argument; transport production test must fail before payload dispatch. |
| Mutation guard | No flag, `--dry-run`, unknown later batch statement, malformed/duplicate evidence | Permit dispatch without confirm or during dry-run; marker-file production test must fail. |

Tests must use `-count=1` when external fixtures or mutants are changed. A helper-only test is insufficient; the named production call site and installed artifact must be exercised.

## Migration from CR revision 4

1. In `internal/browserfacade/outbound.go`, retain `EnforceOutbound` and `OutboundDecision`, replace the regex-first flow with the bounded work queue, JSON scalar walk, escape variants, URL parser, fixed-point rescan, and one normalized name policy.
2. Remove the independent decisions in `safePublicField`, `sensitiveJSONOutputKey`, and `sensitiveOutboundName`; callers may keep convenience functions only if they delegate to the same canonical policy and cannot override its result.
3. In `internal/browserfacade/facade.go`, boundary-check extractor items, advance evidence, and mutation evidence before ordinary JSON decode. Replace `safeErrorDetail` and raw `ExecRunner` detail forwarding with typed generic transport failures.
4. In `internal/browserfacade/config.go`, validate all adapter public metadata through the central policy; do not expose selectors, targets, origins, or transport state in schema.
5. In `internal/browserfacade/cache.go`, keep canonical re-encoding and strengthen descriptor anchoring so every relevant component and final file is no-follow. Cache writes occur only after final clean enforcement.
6. In `internal/browserfacade/render.go` and `cmd/mac-browser-site/main.go`, preserve full buffering and final `WriteOutbound`; make the generic error fallback constant and independent of raw detail.
7. Add the matrix tests first so each reproduced rev1-rev4 attack is red against a deliberately narrowed central policy, then implement until both source and installed entry points pass.
8. Run full uncached tests, vet, build, formatting, diff checks, setup/install, installed attack smokes, cache/external-path absence checks, deterministic extractor tests, pagination tests, and q/grep/m/token-comparison regression checks.
9. Update README, the mac-infra skill reference, LOGBOOK, the task outcome, and validation resource only after the installed bytes match the source candidate.

## Compatibility and security tradeoffs

- **False positives are intentional.** Ambiguous opaque/high-entropy values may be refused. An adapter cannot waive this; use a facade-derived safe handle when the raw identifier is not required publicly.
- **Malformed inputs do not degrade gracefully.** They become unknown/refused rather than partial output or an empty search result.
- **Symlinked cache layouts are unsupported.** Physical-scope proof is more important than compatibility with redirected cache directories.
- **Error detail is reduced.** Users receive stable error codes and generic messages; raw browser stderr is not echoed for debugging because the no-secret claim is stronger than diagnostic convenience.
- **Redaction is narrow.** Redaction is permitted only for structurally parsed URLs whose canonical transformed output rescans clean. Other sensitive or ambiguous material refuses the entire result.
- **The scanner does not infer human semantics.** Documentation must describe the recognized/ambiguous fail-closed contract and must not promise perfect classification of every arbitrary string.

No human-only product or architecture decision is required. These tradeoffs follow the task's existing fail-closed acceptance boundary and the four review verdicts.

## Justified gap record

**Missing piece:** a representation-independent normalization pipeline and typed safe error projection inside the single outbound owner.

**Requirement otherwise incomplete:** R6, the task's explicit no-secret-escape criterion. CR revision 4 proves that a shared function name alone is insufficient when name policy and representation decoding still diverge.

**Consequence of leaving the gap open:** cookie/session/storage material and escaped secret-bearing URLs continue to leave production q/schema/error entry points; later token and encoding variants will repeat the same failure shape.

**How this closes the gap:** all names and representations converge on one bounded decision before lossy decode, cache write, or output; raw transport errors are structurally unable to reach a renderer.

**Self-verification performed before accepting the gap:** checked the Task Description, Scope, and Acceptance Criteria; producer brief; extractor foundation outcome; rework directives and review verdicts revisions 1 through 4; repeated-variant LOGBOOK entries 0145 and 0212; browser-site facade, Safari-session, and Chrome-session references; and their explicit exclusions for cookie/storage export, constructed JavaScript bypass, screenshots, UI scripting, and cursor/session-state serialization. The proposed work implements the existing no-secret and evidence requirements and does not add an excluded browser capability.

## Proportional board decomposition

Keep one board leaf: `TASK-260823-17qhsl` (`design-agent-facing-browser-site-facade`). Do not create sibling stories, research tasks, or separate scanner/cache/error tasks.

The remaining deliverable is atomic: migrate CR revision 4 to this single-owner boundary, prove all production surfaces and installed artifacts, and return one reviewable Change Request. Splitting it would permit independent acceptance of components that cannot satisfy R6 alone and would recreate the ownership gap identified by four review cycles. The current Task already traces to R1-R10 through its Description, Scope, Acceptance Criteria, attached briefs, and this outcome.

No research task is justified: the spec and review evidence resolve the architecture choice, acceptance behavior, and tradeoffs. No open question blocks implementation.

## Developer-ready remaining work

1. Implement the bounded pipeline, canonical name policy, pre-decode evidence validation, and typed transport-error projection behind the existing `EnforceOutbound` owner.
2. Preserve and verify descriptor-rooted cache access, canonical cache rendering, output buffering, deterministic extraction, exact target/origin transport, tri-state pagination, q/grep/m separation, and mutation guards.
3. Add the production-entry and narrowing-mutant matrix for source-built and installed binaries, including stdout/stderr/cache/external-path absence assertions in JSON and compact modes.
4. Run the full gates and installation parity checks, update README/skill/LOGBOOK and task-scoped validation evidence, then hand CR revision 5 to independent review.

## Acceptance checklist for the next developer handoff

- [ ] One exported `EnforceOutbound` owner and one normalized decision state remain.
- [ ] One normalized sensitive-name policy serves fields, JSON keys, assignments, and URL query names.
- [ ] Literal, percent, nested, JSON-escaped, backslash-escaped, case-varied, duplicate, and malformed inputs are boundedly handled.
- [ ] JSON keys and scalar strings are inspected before lossy decode.
- [ ] Cookie, storage, authorization, credential, session-state, and token classes cannot reach output or cache.
- [ ] Refused/unknown decisions carry no inspected value.
- [ ] Transport failures expose only typed generic projections; raw stdout/stderr is never forwarded.
- [ ] Cache traversal is descriptor-rooted/no-follow for every relevant component and file.
- [ ] Cache search returns only canonical validated data and never original JSONL bytes.
- [ ] Complete compact and JSON buffers pass the final boundary before the first write.
- [ ] q projection/batching/schema contracts remain green.
- [ ] grep remains bounded, cache-only, and browser-free.
- [ ] m remains adapter-declared, whole-batch validated, previewable, and confirm-only for dispatch.
- [ ] Pagination unknown/absence semantics remain green.
- [ ] Deterministic extractor/template/predicate and exact target/origin contracts remain green.
- [ ] Every rev1-rev4 attack passes through source-built and installed production entries with non-disclosure assertions.
- [ ] Narrowing mutants fail the named production tests with `-count=1`.
- [ ] Full test, vet, build, format, diff, setup/install, and installed smoke gates pass.
- [ ] Source/installed binary and skill/reference parity is recorded.
- [ ] Updated task outcome and validation artifacts are attached before developer handoff to independent review.
