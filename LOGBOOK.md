# Flight Logbook

> Institutional memory. Concise, factual, high-signal.
> Newest entries first. One block per insight.

## 2026-09-15

### 1726 — Ambiguous Browser Fields Require Value Evidence
- ROOT CAUSE: `internal/docsanitize/sanitize.go` classified generic `name`/`author` and every field containing `address` as PII, corrupting product and organization metadata before facade render/cache.
- FIX: Whole-field classification now covers only unambiguous personal-data headers; generic metadata relies on value-level patterns.
- REGRESSION: `TestRunQProductionEntryPreservesNonPIIValuesInAmbiguousFields` covers JSON/compact stdout, cache, and grep with an adjacent true-name control.

### 1701 — Browser Records Compose PII And Secret Boundaries
- DECISION: `internal/browserfacade/facade.go` keeps secret refusal ahead of one complete-result `internal/docsanitize.SanitizeRecords` pass, then persists and renders only depersonalized records.
- FIX: `internal/docsanitize/sanitize.go` now owns structured field classification, camel-case normalization, stable cross-record placeholders, and invalid-UTF-8 refusal; `internal/browserfacade/cache.go` refuses cache records whose depersonalization is not idempotent.
- SAFETY: Canonical document placeholders are explicitly admitted by `internal/browserfacade/outbound.go`; malformed bracket-shaped values, secret-shaped values, malformed records, and raw-PII cache remain fail-closed.
- EVIDENCE: `TestRunQProductionEntryDepersonalizesListStdoutCacheAndGrep`, `TestRunQProductionEntryRefusesMalformedRecordWithoutOutputOrCache`, and `TestRunGrepProductionEntryRefusesCacheContainingRawPII` drive the public CLI boundary; focused packages pass uncached.

## 2026-08-26

### 2213 — Task-board Restart Double-Prefixes Local Board Paths
- REGRESSION: Cancelling `RUN-260825-ae4432` left element routing pending because the stored `.task-board/.../progress.md` path was resolved again against `.task-board`.
- REGRESSION: Restart then failed while preparing `RUN-260825-6a33b4` for the same double-prefix reason under `.task-board/.resources/BUG-260825-1wsh7n/`.
- STATUS: Story worktree changes remain intact and the queued scheduler advanced to `RUN-260825-0b6a97`; restart recovery for `BUG-260825-1wsh7n` remains pending.

### 2106 — Prompt-Mode Orchestrator Goal Rebind
- ANOMALY: `RUN-260825-94161e` was assigned orchestration without a launch goal; in-run `spawn goal upsert` created `GOAL-260825-69e6cd` revision 1 with `session_manager_pending_unbound`.
- DECISION: Do not launch nested specialists from the unbound parent; yield to the tracked rebound successor required by the goal-provider binding contract.
- STATUS: `BUG-260825-2s6iw4` remains actionable; no producer launch or repository mutation occurred from this orchestrator checkpoint.

### 1058 — Production Entry Owns Chooser Read Evidence
- ANOMALY: The 1021 evidence claim was too broad: its executable harness called `MacChromeWaitForSingleSheet` and `MacChromeWaitForNoSheets` directly, so a permissive wait selected only by `macChromeAXUploadFiles` survived while the named test stayed green.
- FIX: `TestChromeAXUploadProductionPathRefusesUnreadableSheetSequences` now compiles the production Objective-C source with only OS-facing AppKit, Accessibility, sleep, and keyboard dependencies intercepted, then calls the real `macChromeAXUploadFiles` entry for unreadable appearance and closure sequences without touching Chrome or posting real keys.
- EVIDENCE: Routing only the production appearance wait or closure wait through an unreadable-retrying implementation makes the named uncached test fail with exit 1 (`21` and `24`); byte-restored production source passes with exit 0.

### 1021 — Unreadable AXSheets Is Not Chooser Absence
- ROOT CAUSE: `internal/chromectl/ax_darwin.m:179` mapped AX read errors, null values, and wrong-type `AXSheets` values to the same `Missing` status as a successfully read empty array; post-press and final-close waits could retry unknown evidence into a later valid snapshot.
- FIX: A distinct `FileChooserUnreadable` refusal now propagates immediately. The appearance wait retries only proven empty arrays; the close wait retries only the retained exact chooser and accepts only a proven empty array as closure.
- EVIDENCE: `TestChromeAXUploadProductionPathRefusesUnreadableSheetSequences` executes the production Objective-C readers/waits for read-error/null/wrong-type to one-sheet and final read-error to empty sequences. Narrowing unreadable back to `Missing` fails uncached with exit 1.

### 0950 — Native Upload Must Prove A Zero-To-One Chooser Transition
- ROOT CAUSE: `macChromeAXUploadFiles` pressed the nonce-correlated file input and accepted whichever single sheet was attached to Chrome's main window. A chooser already present before the press, or a replacement sheet acquired later, could receive the staged files before DOM attestation rejected the mismatch.
- FIX: The production native bridge admits `AXPress` only after a successful, correctly typed `AXSheets` read reports exactly zero sheets. It retains the one post-press sheet and requires `CFEqual` identity plus fresh frontmost/main-window evidence before every chooser keyboard event; failure cleanup sends Escape only to that same chooser.
- EVIDENCE: `TestChromeAXUploadProductionPathRefusesPreexistingAndReplacedChooser` attacks the production `macChromeAXUploadFiles` call site. Narrowing the precondition from `count == 0` to admit one sheet, removing the identity comparison, or reacquiring an unbound sheet makes the named uncached test fail.

### 0905 — Upload DOM Gates Must Survive The Native Boundary
- ROOT CAUSE: `Session.UploadFiles` validated the file input's type, enabled state, effective visibility, hit target, `multiple`, and `accept` contract only during preparation. The same nonce-bearing input could drift before native selection or before post-selection inspection and still produce `OK:true` from exact filename metadata.
- FIX: One generated validator now owns those DOM decisions and runs during preparation, immediately before Accessibility/native selection, and inside success attestation. Revalidation also requires the same unguessable state key and Accessibility marker.
- EVIDENCE: `TestUploadFilesProductionPathRevalidatesSameInputBeforeNativeAndAttestation` drives `Session.UploadFiles` and executes the generated page programs. It refuses `.pdf` to `.png` drift before AX with zero native calls and refuses ancestor-opacity/type drift after selection without a success result. Before the fix all three attacks returned `OK:true` (focused expected-red exit 1).

### 0831 — Upload Metadata Attestation Must Consume Matches
- ROOT CAUSE: `internal/chromectl/upload.go` verified the selected `FileList` count and checked each actual `(name,size)` against a map of expected files, but never consumed a match. Expected `a.pdf,b.pdf` therefore admitted actual `a.pdf,a.pdf` and emitted a misleading success attestation for the intended names.
- FIX: The generated production inspection deletes each matched expected basename and refuses a repeated actual name or any unmatched expected entry, while preserving order-independent exact matches.
- EVIDENCE: `TestUploadFilesProductionPathRequiresOneToOnePostSelectionMetadata` drives `Session.UploadFiles`, executes its generated inspection program, rejects duplicate substitution, wrong size, and wrong count without a success result, and accepts reordered exact metadata. Narrowing the production loop to omit match consumption makes the duplicate case fail.

### 0751 — Upload Visibility Must Reject Unbounded Rendering Effects
- ROOT CAUSE: `internal/chromectl/upload.go` checked computed `opacity` but admitted an ancestor with `filter: opacity(0)` because Chrome still reported opacity `1`, a positive rectangle, and the exact hit target.
- DECISION: The bounded upload visibility contract admits only computed `filter: none` and `mask-image: none` through the 64-ancestor chain; non-default filter or mask effects refuse before focus or Accessibility.
- EVIDENCE: `TestUploadFilesProductionCompositionRefusesDOMAcceptAndEffectiveVisibilityBeforeNativeAccess` executes the generated production program and requires filtered and masked ancestors to return `input-hidden` with zero focus/AX calls.

### 0727 — DOM Accept Must Constrain Native Upload
- ROOT CAUSE: `internal/chromectl/upload.go:363` ignored the file input's `accept`; a page declaring `.png` or `image/png` admitted staged PDF files before native selection.
- FIX: The production page gate accepts only bounded extension, exact MIME, and standard media wildcard tokens and requires every staged filename/fixed MIME mapping to match before focus.
- EVIDENCE: `internal/chromectl/upload_test.go:214` executes the generated production page program through `Session.UploadFiles`; narrowing mismatch refusal to an impossible empty-token branch makes the named test fail before the expected refusal.

### 0726 — Upload Visibility Is An Ancestor And Hit-Test Property
- ROOT CAUSE: Input-local opacity and rectangles admitted controls hidden by zero-opacity or hidden ancestry; a synthetic page returned `ready` for an input the user could not see.
- FIX: `internal/chromectl/upload.go:356` bounds ancestor inspection to 64 elements and requires the exact input to win a bounded viewport hit test before assigning the Accessibility nonce.
- EVIDENCE: Narrowing opacity rejection to `node===input` makes the production-composition ancestor test reach the focus trap and fail; restored source passes with zero AX calls.

### 0640 — Private Upload Decoder Errors Must Not Echo Field Names
- ROOT CAUSE: `DecodeUploadRequest` wrapped `json.Decoder` errors, so an unknown JSON field name supplied on private stdin could be printed by `runUpload`; a local path or token embedded in that name crossed the privacy boundary.
- FIX: `internal/chromectl/upload.go:80` collapses malformed/unknown-field decoding to one fixed diagnostic; the production CLI negative proves the marker reaches neither execution nor stdout/stderr.

### 0639 — Canonical Origin Validation Must Normalize Case Explicitly
- ROOT CAUSE: `validateExactTarget` claimed lowercase origins but `browsersession.OriginOf` preserves host case, so `https://Example.com` passed and reached page-context automation.
- FIX: `internal/chromectl/trusted_input.go:181` explicitly requires the complete origin string to be lowercase; `TestUploadFilesProductionPathRejectsNonExactTargetBeforePageOrNativeAccess` reproduced the pre-fix reach and now refuses before browser/native calls.

### 0638 — Visible File Inputs Need Geometry And Opacity Gates
- ROOT CAUSE: The upload DOM gate checked only `getClientRects().length`, `display`, and `visibility`; zero-sized, off-viewport, `hidden`/`aria-hidden`, and `opacity:0` inputs could reach the native chooser path.
- FIX: `internal/chromectl/upload.go:325` requires a positive on-viewport rectangle and rejects explicit hidden/opacity states; production-path refusal tests bind DOM refusal, target drift, trusted change, exact metadata, and AX non-invocation to `Session.UploadFiles`.

### 0630 — Guarded Upload Entered Through Another Task Checkpoint
- ANOMALY: `git log --follow -- internal/chromectl/upload.go` shows guarded Chrome upload first entered the Story branch in `a46d126`, the checkpoint for `BUG-260825-2s6iw4`; `TASK-260826-10ftog` has no Change Request.
- SCOPE: The same commit carried `cmd/mac-chrome-session/main.go`, `internal/chromectl/upload.go`, README/setup, and the mac-infra Chrome-session contract; the current working tree already matches that implementation at `HEAD`.
- DECISION: Do not restore the worktree's reverse/stale index or manufacture a code delta. Revalidate the production path in `HEAD`, publish the task candidate with task-scoped evidence, and require independent review to inspect the named upload call sites despite the inherited baseline.

### 1615 — Four Leaks, One Missing Owner: Seal the Boundary, Not the Site
- FINDING: `fetch-file` leaked the protected resource four times in a row, each time at a different surface: production argv (rev1), forwarded child stderr/stdout (rev2), a self-minted nested `origin-mismatch` observed value (rev3), and — found by independent review of rev4 — the output preflight path, where `prepare output: inspect path: lstat .../<private path>: not a directory` printed the explicit private output path and the syscall text. `runFetchFile` had seven distinct print sites (flag parser on stderr, decode, validation, preflight, `FormatAutomationError` for transfer, commit, success), and `Session.FetchFile` returned whatever its internal branches happened to produce.
- ROOT CAUSE: Not four bugs. One missing owner. Every site made its own formatting decision, so each fix was local and the next unaudited site inherited the same freedom. Negative-evidence shape: **many variants, one unowned decision** — and, at each individual site, **bypass path around the check**.
- FIX (per `BUG-260825-2s6iw4_privacy-boundary-decision.md`): one closed diagnostic type `chromectl.FetchFileDiagnostic` with a single private `uint8` enum field — no wrapped error, no detail string, no `Unwrap`; a total switch over the enum returns literals only, and an unknown code collapses to the safe catch-all. `Session.FetchFile` gained a mandatory outer normalizer: every non-nil public error is replaced by a fresh diagnostic, so a branch that forgets to classify itself degrades to `unverifiable` instead of opening a bypass. `cmd/mac-chrome-session` gained one `emitFetchFileDiagnostic` call site that accepts only that type; the fetch-file `flag.FlagSet` writes to `io.Discard` so the flag package cannot be a second formatter. `errors.Is` for `ErrTargetMissing`/`ErrOriginMismatch` is preserved through an `Is` method; `errors.As` to the detail-bearing lower-layer types now fails by construction.
- EVIDENCE: eight *narrowing* mutants, all killed with `-count=1` (`.temp/BUG-260825-2s6iw4/mutants.py`): seal narrowed to the start seam only (poll/chunk unsealed), nested `OriginMismatchError.Observed` passthrough restored, a renderable `detail` field added, the CLI emitter printing `err.Error()` for the preflight branch, the flag parser given `stderr` back, unknown codes retained and rendered, the commit branch routed around the emitter, and a lower-layer transport kind appended to a fixed message. Production-entry negatives drive `run(fetch-file)` for output preflight (three real filesystem shapes), output commit, retired `--resource`, and fifteen forged transport/page shapes; a static AST guard asserts `runFetchFile` contains no `fmt.*` call at all and the emitter exactly one, with `runUpload` as the positive control that the scan can see a print.
- ANOMALY (own error, recorded): the first version of the shared assertion compared the produced message against `NewFetchFileDiagnostic(want).Message()` — the implementation against itself. The transport-kind mutant changed both sides and survived. Both test packages now pin an independent literal table.
- LESSON: When the same defect class reappears at a new surface for the third time, stop patching sites and give the decision an owner. And an assertion that derives its expectation from the code under test is not an assertion.

### 0912 — A Sealed Envelope Authenticates Shape, Not Provenance
- FINDING: The 0204 seal below discarded child *streams*, but the sealed transport still forwarded one field out of the child's *structured* response. `runJavaScriptPrivate` parsed the nested `browsersession` guard envelope and returned `*OriginMismatchError` intact, and `runFetchFile` printed it through `FormatAutomationError`. A hostile child that minted a valid outer private-transport seal wrapping a valid nested `origin-mismatch` envelope, with `origin` set to a copy of its own stdin, put the full authenticated URL and both query parameter names back on the terminal. The previously shipped `echo-then-forged-seal` case missed this: its nested value was malformed, so it landed on the fixed unreadable-response branch and never reached the origin classification.
- ROOT CAUSE: Both sentinels prove envelope *shape*; neither proves *provenance*. The seal was read as an authentication of the responder, so a well-formed field inside it was treated as trusted data. It is not: the same child received the resource-bearing program.
- FIX: `internal/chromectl/trusted_input.go` returns the fixed `errSealedOriginMismatch` on this path. It still wraps `browsersession.ErrOriginMismatch`, so `slack.go` and the CLI keep the classification, but the child-supplied `Observed` value is dropped whole. The unsealed exact-target path (`resolveExactTarget`) still reports the observed origin — that child never receives the protected resource.
- EVIDENCE: `TestFetchFileProductionEntryNeverReflectsForgedNestedOriginMismatch` drives the real `run(fetch-file)` against two narrowed forges (nested `origin-mismatch`, and nested `ok` with a drifted origin), reads back what the child actually received as a positive control, and additionally asserts the drift classification survives so a delete-only mutant cannot pass. The narrowing mutant that restores `errors.As` passthrough of `Observed` fails both subtests.
- LESSON: Discarding a channel's *bytes* is not the same as distrusting its *values*. Enumerate every field of a parsed response that can be echoed by a party holding the secret, not just the raw streams.

### 0529 — JSON Maps Are Too Late for Duplicate-Key Gates
- ROOT CAUSE: `sanitizeSlackResponse` decoded Slack JSON into `map[string]any` before sanitizing keys or counting nodes. Go collapsed identical and escape-equivalent object members first, so `Session.SlackRead` could return the last value and 20,001 duplicate members counted as one.
- FIX: `internal/chromectl/slack.go` now consumes JSON tokens in source order, counts every raw value, sanitizes keys before insertion, and records decoded/normalized collisions without overwriting. Object parsing continues after a collision so the raw-node ceiling still refuses an oversized duplicate-member response.
- EVIDENCE: `BUG-260825-4fodlv` production tests drive identical, escaped-equivalent, nested, and over-bound duplicates through `Session.SlackRead` and the CLI envelope; narrowing collision detection to nested objects or widening the node ceiling makes the named tests fail with `-count=1`.

### 0438 — LaunchAgent Absence Must Come From Exit Evidence, Not The Service Label
- ROOT CAUSE: `internal/browsersession/heartbeat.go:isMissingLaunchAgent` searched the composed `launchctl` error for the bare substring `113`. Valid heartbeat names and UIDs may contain those digits, so `hb113` plus a genuine `bootout` permission failure was misclassified as an absent service after expiry had removed its managed artifacts.
- FIX: `runLaunchctl` now preserves the verb, exit code, and child output in a typed error. Missing `print` requires exit `113` plus the `Could not find service` response; missing `bootout` requires exit `3` plus the exact `Boot-out failed: 3: No such process` response. Unstructured test hooks accept only whole sentinel messages.
- EVIDENCE: `internal/browsersession/heartbeat_test.go:TestInspectExpiredHeartbeatDoesNotLaunderBootoutFailureWhenIdentityContains113` drives `Inspect -> expire -> runLaunchctl` with name and UID `113`, a real child exit `1`, and `Operation not permitted`; the failure must propagate instead of attesting successful expiry.
- LESSON: A failed lifecycle action is not evidence of absence. Classify child-process state from owned structured fields, never from arbitrary digits in a rendered diagnostic.

### 0204 — A Sealed Input Path Is Only As Private As Its Failure Diagnostics
- FINDING: `fetch-file` moved the protected resource out of production argv and into a private stdin envelope, and every *refusal* string was fixed — but the layer below still forwarded untrusted child bytes. `runJXAStdin` copied raw `osascript` stderr (then stdout) into its error, `runJavaScriptPrivate` embeds the resource-bearing page-context program in that child's stdin, and `runFetchFile` prints the error through `FormatAutomationError`. A child that echoed its own stdin on failure put the full authenticated URL, both query parameter names, and their opaque values on the operator's terminal.
- ROOT CAUSE: The privacy boundary was drawn at the decoder, where the input arrives, and not at the transport, where the same secret leaves. Decoder refusals were audited and fixed-string; the transport's error path was treated as a diagnostic rather than as an output channel carrying the same secret. Negative-evidence shape: **bypass path around the check**.
- FIX: `internal/chromectl/trusted_input.go` seals the transport. Child stdout and stderr are discarded on failure and replaced by a typed `PrivateTransportError` whose `Kind` comes from a closed Go-side set (`child-exit-status`, `child-unavailable`, `page-context-execute-failed`, `unverifiable-response`). Target loss survives because the JXA program now *returns* a sentinel-sealed `window-missing`/`tab-missing` envelope instead of throwing, so classification no longer depends on child text, and the program's `catch` arm drops the caught error whole — a JXA execute error can quote the program it failed on.
- EVIDENCE: `TestFetchFileProductionEntryNeverReflectsResourceFromPrivateTransportDiagnostics` drives the real `run(fetch-file)` against five hostile children (echo stdin to stderr / stdout / both / on exit 0 / inside a forged seal) and reads back what the child actually received, so an absent marker cannot be a vacuous pass. Mutants: forwarding both streams (pre-fix) is caught, and so is the *narrowed* mutant that keeps stderr discarded and forwards only stdout. A sixth mutant that re-derives target-missing from child stderr text is caught by `child-text-alone-is-not-target-loss`.
- LESSON: When a secret is carried on a private channel, enumerate every path by which that channel's bytes can come back out. A hardened decoder and a chatty transport are the same leak.

### 0158 — Bound Integers Before They Become time.Duration
- ROOT CAUSE: `DecodeFetchFileRequest` compared `time.Duration(timeoutMs) * time.Millisecond` against the 5-minute maximum. `time.Duration` is int64 nanoseconds, so the multiplication wraps: `timeoutMs=288230376151711754` became `10ms` and was accepted by a bound that exists precisely to reject it.
- FIX: compare `int64(wire.TimeoutMS)` against `MaximumFetchFileTimeout.Milliseconds()` *before* converting.
- EVIDENCE: The overflow fixture must be a `var`, not a `const` — as an untyped constant the compiler rejects the wrapping conversion outright, which is exactly why the runtime path had no equivalent guard. Three mutants pin the bound from both sides: reverting to post-conversion comparison, widening it to 4x, and narrowing it to 299999ms all fail, the last one on the positive `exact-maximum-still-accepted` control.
- LESSON: A bound checked after a lossy conversion is not a bound. Adjacent-edge cases (`300001`) prove nothing about integer overflow; narrow *and* widen the gate to show the test covers the class.

### 0108 — Ad-Hoc Codesign Without `--requirements` Rebrands Every Rebuild
- ROOT CAUSE: `codesign --force --sign - --identifier X` derives the designated requirement from the **cdhash**, not the identifier. Every rebuild changes the cdhash, so macOS saw a brand-new code identity — and a brand-new App Background Activity item — for each build of the heartbeat launcher.
- EVIDENCE: Two builds of `cmd/mac-chrome-session` differing only by `-ldflags -X main.Version`, signed the base way, produced `designated => cdhash H"1312eeb1..."` and `designated => cdhash H"51893f84..."`. Signed with `--requirements '=designated => identifier "works.relux.mac-infra.browser-session"'`, both produced the identical identifier-only requirement despite different content hashes.
- FIX: `scripts/setup.sh` passes an explicit `--requirements` for both `mac-chrome-session` and `mac-safari-session`, verifies the observed requirement with `codesign -d -r-`, and installs the signed bytes at one stable path `~/Library/Application Support/mac-infra/browser-session/bin/mac-browser-heartbeat-launcher`.
- LESSON: A stable TCC/background identity needs BOTH halves — an explicit identifier-only designated requirement *and* a stable on-disk program path. Content-addressed pinning (`mac-browser-session-<sha>`) guaranteed the opposite of what it looked like it guaranteed.
- SCOPE: Reviewer evidence for `TASK-260824-2x6qiu` (`RUN-260825-1027f1`), artifact `TASK-260824-2x6qiu_review-verdict.md`.

### 0040 — Safari Fetch Publication Requires Byte Attestation
- ROOT CAUSE: `fetch-file` decoded and published accumulated chunks without comparing them to Safari's `blob.size`; a lost page-context job returned an empty chunk that could remain valid base64 and silently truncate the file.
- FIX: `cmd/mac-safari-session/main.go` refuses empty chunks and decoded/browser byte-count mismatch before writing output or metadata.
- EVIDENCE: Production `run()` tests prove complete reassembly and refuse missing-middle-chunk and browser-size-mismatch transfers without replacing an existing destination; a sentinel-valid `outcome:"ok"` with the wrong origin is also refused.
- SCOPE: `TASK-260615-1tlcpm`; no cookie, storage, authorization-header, focus, heartbeat, or Chrome behavior changed.

### 0031 — Full Parallel Go Suite Can Starve Fetch-File Timeouts
- ANOMALY: `go test -count=1 ./...` timed out three sibling `cmd/mac-chrome-session` fetch-file cases only under concurrent package load; the two exact tests passed uncached in isolation and the full uncached suite passed with `-p 1`.
- EVIDENCE: `.temp/TASK-260824-2x6qiu/go-test-full-01.log`, `go-test-sibling-fetch-isolated-01.log`, and `go-test-full-serial-01.log` record exit 1/0/0 respectively.
- STATUS: Heartbeat scope is green; no fetch-file production or test code changed under `TASK-260824-2x6qiu`.

### 0002 — The Privacy Boundary Is The Production Process Argv, Not The Child Process Argv
- FINDING: `fetch-file` advertised a private-stdin transport and was tested for it, but the test asserted only that the resource was absent from the child `osascript` argv. The value was declared as `--resource` on the `mac-chrome-session` flag set, so it sat in the *production* process argv the whole time. Independent review reproduced it directly: the candidate binary was started with a synthetic marker in `--resource`, stopped before browser work, and `ps` showed `production-cli-resource-visible-in-process-argv=true`.
- ROOT CAUSE: The private transport began one process too late. A correct-looking test around the wrong boundary made the gap invisible: the child argv is a proxy for the property that matters, and the proxy was clean while the real boundary leaked. In an agent workflow the command line is durable tool/session evidence, and an interactive shell can persist it in history, so argv is exactly where a protected document or sticky identifier must not appear.
- FIX: `fetch-file` no longer declares `--resource`, `--max-bytes`, or `--timeout`. It requires `--request-stdin` and reads one bounded versioned envelope (`chromectl.DecodeFetchFileRequest`): a single JSON object, at most 8192 bytes, resource at most 4096 bytes, only `version`/`resource`/`maxBytes`/`timeoutMs`, unknown fields and trailing JSON refused, every refusal a fixed string that cannot echo the envelope. All exact-target, same-origin, size, timeout, and atomic-`0600` guards are unchanged.
- EVIDENCE: `TestFetchFileKeepsProtectedResourceOutOfProductionCLIArgv` builds the real binary, blocks it on the unclosed stdin pipe so the observation cannot race process exit, and reads its argv with `ps -ww` from outside. Four mutants, all caught: reintroducing `--resource` as a pass-through flag; making `--request-stdin` optional with a positional argv fallback; blinding the `ps` read so a failed read would masquerade as a clean absence; and planting the marker in the real argv so the leak assertion itself is proven live.
- LESSON: When a test proves a privacy property about process A by inspecting process B, name the process in the assertion. "Absent from the child argv" and "absent from our argv" read identically in a test name and differ completely in what they protect.
- OUT OF SCOPE, STILL OPEN: `mac-safari-session fetch-file` still takes `--resource` on argv (`README.md`, `agents/skills/mac-infra/references/safari-session.md`). Same defect, different binary and task; not touched here.

### 0001 — Browser URL Redaction Must Be Structural, Not Name-Based
- FINDING: While proving the Chrome sealed-download path, `mac-chrome-session list` emitted the full query string of an authenticated statement tab and its download tab. `browsersession.RedactSensitiveURL` filtered by parameter name against a fixed denylist (`code`, `token`, `signature`, ...), and the site carried its opaque document and sticky identifiers under names that denylist never heard of.
- ROOT CAUSE: A parameter-name denylist cannot fail closed against a site that names its own identifiers. Worse, the identifier is as often the parameter *name* as the value (`?9f3a...=1`, `?9f3a...` with no `=`), so even redacting every value under an unknown name still leaks.
- FIX: `RedactSensitiveURL` now keeps only scheme, host (including a nonstandard port) and path. The whole query collapses to `?[redacted-query]`, the fragment to `#[redacted]`, user info is dropped, and payload-carrying opaque URLs (`data:`, `javascript:`, `view-source:`, `mailto:`) become `[redacted-opaque-url]`. `about:` and `blob:` stay identifiable.
- EVIDENCE: A narrowing mutant that restores name-based filtering fails 9 subtests; a widening mutant that admits `data:`/`javascript:`/`view-source:`/`mailto:` fails 4. `TestListNeverEmitsAuthenticatedQueryIdentifiersUnderUnknownParameterNames` drives the real `Session.List` production path. Live `list` after install shows the previously leaking Sber download tab as `?[redacted-query]`.
- CONSEQUENCE FOR CALLERS: A download URL can no longer be recovered from `list` output. Read the link in page context and pass it to `fetch-file --request-stdin` in the same turn. This entry originally said `fetch-file --resource`, and the "stays out of argv" claim attached to that flag was wrong — see entry 0002.

### 0000 — Same-Origin Guards Need Parent-Domain And Port Negative Cases
- FINDING: `fetch-file`'s exact same-origin comparison survived a mutant that narrowed it to `strings.HasSuffix(expectedOrigin, resolved.Host)` — every existing test still passed. That mutant admits `https://example.com/doc` from an `https://mail.example.com` guard, and `https://com/doc` from any `.com` guard.
- FIX: Added parent-domain, sibling-subdomain, suffix-host, host-substring, port-drift and host-case-drift negatives to both `normalizeFetchFileRequest` and the `fetch-file` CLI entry. The mutant now fails at both levels.
- LESSON: An origin equality check is only proven by a mutant that *narrows* it to a looser relation. Cross-origin tests that use an unrelated host pass under suffix, prefix and substring matching alike.

## 2026-08-25

### 2329 — Trusted Input Focus Must Follow DOM Preparation
- FINDING: A live authenticated non-secret autocomplete fixture exposed intermittent `native-focus-unverified` after exact focus: DOM nonce preparation happened after activation, and the native bridge also relied on a stale `NSRunningApplication.active` snapshot.
- FIX: Prepare the exact guarded DOM target first, perform the authorized exact focus immediately before native typing, and attest foreground ownership from `NSWorkspace.frontmostApplication` under a bounded settle window while retaining the unique main-window and nonce gates.
- EVIDENCE: The initial and first bounded-wait smokes refused with exit 1; after the ordering and foreground-evidence fix, trusted text passed and the full trusted text/named-option surface passed 3/3 consecutive authenticated fixture runs. Fixtures were removed in-command; identifiers and values were not persisted.

### 2258 — Installed Legacy Heartbeats Surface Migration Without Mutation
- FINDING: Installed no-focus `heartbeat list` reports five existing Chrome records as `migration-required` with `errorKind: missing-deadline`; no browser dispatch, state rewrite, or automatic restart occurred.
- DECISION: Do not invent lifetimes for existing user sessions. Migrate each explicitly with `heartbeat restart --name NAME --ttl DURATION` or an RFC3339 deadline selected for that session.

### 2243 — Heartbeat Builds Share One Expiring Installed Identity
- ROOT CAUSE: `internal/browsersession/heartbeat.go` rendered each LaunchAgent with a content-addressed build copy, so ordinary rebuilds changed the executable path and macOS registered another App Background Activity identity.
- DECISION: Chrome and Safari heartbeats execute `~/Library/Application Support/mac-infra/browser-session/bin/mac-browser-heartbeat-launcher`; `scripts/setup.sh` atomically replaces that signed path while preserving `works.relux.mac-infra.browser-session`.
- SAFETY: Every new start requires exactly one future `--ttl` or RFC3339 `--deadline`; `Run` and `Inspect` remove state/plist/log before self-`bootout` at expiry without browser dispatch or focus.
- MIGRATION: Legacy content-addressed or deadline-free state reports `migration-required`; `heartbeat restart --name ... --ttl|--deadline` preflights before stopping it, removes the old pinned copy, and starts on the stable launcher.

### 2221 — Safari Heartbeats Need A Native Signed Lifecycle Surface
- DECISION: `cmd/mac-safari-session/main.go` owns Safari `heartbeat start|status|list|stop` while reusing `internal/browsersession`; it accepts only positive exact window ids and canonical HTTPS origins, lists only Safari entries, and refuses Chrome-owned names in the shared namespace.
- FIX: `scripts/setup.sh` gives `mac-safari-session` the stable designated requirement `works.relux.mac-infra.safari-session` before a content-addressed copy becomes the LaunchAgent executable.
- SAFETY: The atomic window/origin probe persists only bounded outcome metadata; cookies, authorization material, and page content remain in Safari and do not enter heartbeat state or logs.
- BLOCKED: Installed exact-window FNS direct probe passed, but the first LaunchAgent probe timed out and rolled back cleanly; the user must grant Safari Automation consent to the new managed executable before the live lifecycle can pass.

### 2202 — Chrome Exact Focus And Trusted Form Input Need One Fail-Closed Contract
- REPRODUCTION: Sanitized incident evidence records that `list` returned one exact existing Chrome window/tab pair, while focusing that pair after cross-origin navigation failed with Apple Events `-1728` (`Can not get object`). A guarded DOM value assignment changed the autocomplete input value but produced no trusted input event, no option list, and no enabled continuation state. No target IDs, URLs beyond origin, field values, account data, cookies, storage, headers, or tokens are retained.
- ROOT CAUSE: Focus dereferenced a filtered Chrome tab proxy's stale `index` property after navigation, and generic page JavaScript cannot mint trusted keyboard interaction. The CLI had no bounded native bridge tied to the exact tab/origin and explicit human authorization.
- FIX: Explicit `focus` re-enumerates fresh arrays, checks the exact IDs/origin around selection, moves that exact window to the front without title matching, and reattests the same front window/tab/origin. Explicit `trusted-input` adds a bounded stdin request for one text/search input and optional exact-text autocomplete option, correlates nonce-marked Accessibility elements inside Chrome's unique main window, verifies foreground/main focus immediately before native text and option actions, posts only a fixed non-secret append/Backspace pulse, and requires trusted DOM events before boolean success attestation. Live diagnosis also removed an invalid cgo function-type dispatch hidden by test doubles and replaced an unstable `cdhash` signing requirement with the explicit identifier required for durable TCC consent.
- SAFETY: Silent commands remain no-focus. Both visible paths require exact IDs, canonical origin, and `--human-authorized`; missing/ambiguous/drifted targets, unreadable evidence, oversized input, too many options, untrusted events, and Accessibility/TCC refusal fail closed. Field and option values never enter argv or normal output/logs.

### 2148 — Chrome Protected Downloads Need A Sealed Fetch, Not Native Download UI
- REPRODUCTION: The incident reports one protected native download followed by a blocked second download. A privacy-safe current-Chrome probe fetched a non-sensitive authenticated same-origin app shell in page context and dispatched two native download-link activations; page state recorded 2/2 dispatches with no fetch error, while 0/2 task-named files materialized and the foreground app stayed unchanged. Current headless policy therefore reproduces the native-path failure in a stricter form, although the original exact 1/2 sequence was not independently recreated.
- ROOT CAUSE: The browser download manager owns multi-download permission and user activation, while `mac-chrome-session` previously had no exact-tab file-transfer primitive; retrying clicks or focus changes cannot provide a deterministic headless contract.
- FIX: `mac-chrome-session fetch-file` uses private-stdin, tool-authored same-origin `fetch` with browser-owned credentials, exact window/tab/origin guards on every operation, byte/deadline limits, sanitized status metadata, and atomic explicit `0600` output. Sequential calls reuse the authenticated page without cookies, headers, storage, URLs, or page content crossing the command boundary.
- SAFETY: Cross-origin/credential/fragment URLs, redirects, target loss, origin drift, busy state, malformed envelopes/chunks, size overflow, timeout, and output failures all refuse without replacing an existing destination or falling back to stdout.

### 2018 — Chrome Run-JS Owns Private Output Publication
- FIX: `cmd/mac-chrome-session/main.go` preflights a same-directory private temp file, writes the guarded result, and atomically renames it to `--out` with mode `0600` for both `--script` and `--file`.
- SAFETY: Invalid/preflight failures dispatch no page payload; guard or publish failures create no final artifact and never fall back to page content on stdout.
- EVIDENCE: A whitespace-gate narrowing mutant failed the named production-entry test; targeted race, full tests, vet, build, signed setup/install parity, and no-focus live `--script`/`--file` smokes passed under `BUG-260825-2pn2en`.

### 2008 — Chrome Output Drift Was Narrower Than Reproduction
- FINDING: `BUG-260825-2pn2en` reproduced installed `run-js --out` rejection, while current source and installed help already agreed on `--file`; the attached note's source-only `--script` observation was stale.
- ROOT CAUSE: Chrome `run-js` had no owned output-artifact path, while README and the installed Chrome skill documented only stdout capture; shell redirection remained the privacy-safe fallback.
- DECISION: Preserve the existing exact target/origin and browser-secret guards; add preflighted atomic `0600` publication shared by `--script` and `--file`, with no page-content fallback to stdout.

### 1944 — Token Prefix Boundaries Were an Evasion Surface
- FINDING: CR revision 1 showed that alphanumeric glue such as `axoxb-*` or `zzBearer ...` bypassed the boundary-aware span patterns in both Slack response keys and values, while the randomized differential test asserted only detector agreement rather than sanitized-output leak freedom.
- FIX: Treat the distinctive xox/xapp/Bearer/JWT shapes as sensitive at any string offset, assert that a 200,000-input corpus contains no token-shaped span after sanitization, and pin the secret-key branch, pre-branch collision guard, and whitespace-wrapped URL offset with production-path tests under `BUG-260825-3ewejy`.

### 1915 — Slack Response Keys Need Their Own Secret Boundary
- FINDING: The sealed Slack response sanitizer redacts token-shaped scalar spans, but JSON object keys are preserved verbatim; a synthetic `xoxb-*` key can therefore cross `Session.SlackRead` unchanged.
- DECISION: Keep the accepted scalar span-redaction scope closed and track key sanitization separately as `BUG-260825-3ewejy`, including deterministic collision handling and nested-map production-path tests.
- CONTEXT: CR revision 5 accepted the scalar/URL/overlap/cost contract with 16/16 mutants killed; this pre-existing map-key gap is non-blocking for that delivery but must not be lost in chat context.

### 1823 — Partial Overlaps Must Prove Union Extension
- FINDING: A contained Bearer/xox overlap proved duplicate-span suppression but never exercised the branch that extends a merged span past its current end.
- FIX: `internal/chromectl/slack_test.go:352` drives a partially overlapping JWT/Bearer value through `Session.SlackRead`; deleting only `internal/chromectl/slack.go:792` now fails by exposing the synthetic Bearer tail.

### 1751 — Slack Token Scanner Cost Is Response-Bounded
- REGRESSION: Rescanning after each rejected token boundary made a hostile in-bounds Slack response quadratic and allowed sanitization to outlive the caller deadline.
- FIX: Token regexps now encode their left boundary and expose only the token capture span, allowing one linear `FindAllStringSubmatchIndex` pass per secret class while retaining overlap union and nested-start detection.
- EVIDENCE: Production `Session.SlackRead` exercises an exact 256 KiB adversarial response under a 3-second cost bound; the CR revision 2 scanner fails this named test while the linear scanner preserves the hostile synthetic prefix and redacts the terminal token.

### 1727 — Slack Span Scanner Rescans Nested Starts
- REGRESSION: Post-filtering non-overlapping regexp matches dropped valid xox/xapp starts nested inside a boundary-rejected match; exactly-three-segment JWT matching left 4+/5-part compact-token tails raw.
- FIX: The revision-2 scanner resumed rejected searches at the next byte, consumed additional compact-token segments, and unioned overlapping secret classes before replacement; entry 1751 records the subsequent linear-scan correction.
- EVIDENCE: Six production `Session.SlackRead` narrowing mutants fail named tests; uncached full tests, vet, build, signed install, and count-only `REF-SYN-4242` live smoke pass with zero raw token shapes.

### 1658 — Slack Secret Redaction Preserves Safe Message Text
- ROOT CAUSE: `internal/chromectl/slack.go` replaced any string containing an xox/xapp, Bearer, or JWT shape with one marker, discarding non-secret Slack message bytes.
- FIX: The sanitizer collects every bounded secret span, unions overlaps, and replaces spans in place; structured secret keys, sensitive URLs, depth/node/size limits, exact guards, and generic storage refusal remain separate fail-closed layers.
- EVIDENCE: Production `Session.SlackRead` and CLI-envelope tests cover repeated/adjacent classes, punctuation, Unicode, malformed JSON, composite secret keys, URLs, and bounds; three narrowing mutants fail named production-path tests with `-count=1`.

### 1627 — Slack Sealed Reads Use Closed Typed Decoders
- DECISION: `internal/chromectl/slack.go` admits only five added reads; search query/page bounds are 512 bytes/1000, conversation ids are `C|D|G` plus 8..31 alphanumerics, and timestamps are bounded `seconds.fraction` values.
- SAFETY: Every method rejects unknown/trailing fields and secret-shaped strings; supplied `team_id` must equal the exact guarded workspace before `osascript`; page-origin/workspace guards, browser-only authorization, response bounds, and generic `run-js` storage refusal are unchanged.
- EVIDENCE: A pagination-gate narrowing reached fake `osascript` and failed the named production-entry test; focused/full tests, vet, build, setup/install, installed-artifact checks, and content-free live smokes for all seven reads passed under `TASK-260825-ghny8q`.

### 1601 — Refusal Tests Must Own Independent Fixtures And Phase Evidence
- ROOT CAUSE: Browser-secret tests iterated the production blocklist itself, so removing `cookiestore` or `opendatabase` removed their own cases; Slack tests merged start and poll sources, so poll guards masked missing start guards.
- FIX: `internal/browsersession/session_test.go` and `cmd/mac-chrome-session/main_test.go` pin a literal blocked-token contract; `internal/chromectl/slack_test.go` captures the production start evaluation separately and verifies origin/workspace guards precede secret lookup and request start.
- EVIDENCE: Narrowing the Slack start guards, `cookiestore`, or `opendatabase` independently makes the named production-path tests fail with `-count=1`; production sources were restored byte-for-byte before the green suite.

### 1511 — Slack Browser Authorization Stays Sealed In Page Context
- FINDING: Slack Web cookie-only `/api/auth.test` returned `not_authed`; the selected workspace's `localConfig_v2` web token plus companion cookies produced successful `auth.test` and bounded `conversations.list` calls.
- DECISION: `internal/chromectl/slack.go` owns a compiled `auth.test`/`conversations.list` allowlist and atomically verifies exact Chrome target, `https://app.slack.com`, and `/client/<workspace-id>` before locating authorization and starting the request.
- SAFETY: Token material never leaves page context or enters argv/environment; generic `run-js` storage guards remain unchanged; recursive response sanitization and bounded stdin/output/depth fail closed.
- MILESTONE: Installed signed CLI passed both live reads without focus change, persisted content, or heartbeat state regression.

## 2026-08-24

### 0415 — Explicit Final Cache Symlinks Are Failed Reads, Not Absence
- ROOT CAUSE: `Cache.Grep` grouped final symlinks with unrelated directory entries and skipped them before the descriptor-rooted open, so an explicit `--file` request returned a successful empty result.
- DECISION: Keep the descriptor-rooted/no-follow cache owner and return `CACHE_SCOPE_REFUSED` when the requested basename is a final symlink; unrequested symlink entries remain ignored during a bounded cache scan.
- EVIDENCE: The compact/JSON `runGrep` production test asserts typed nonzero refusal, no external marker or path in stdout/stderr, and byte-preservation of the external file. Narrowing only the refusal back to `continue` makes the named test fail with `-count=1`.
- SCOPE: `TASK-260823-17qhsl`; no CLI, renderer, outbound scanner, q/m, pagination, extractor, or browser-transport behavior changed.

### 0344 — URL Hostnames And Path Components Stay Inside The Canonical Boundary
- ROOT CAUSE: Recognized URLs were removed from the general scanner remainder before their hostname and individual decoded path components reached the shared name and credential policy, so revision 6 admitted credential and browser-session shapes in those positions.
- DECISION: Keep `EnforceOutbound` as the sole owner and structurally classify `Hostname()` plus every bounded `PathUnescape` component through the existing normalized name policy and credential/opaque-value scanner; malformed or exhausted component decoding remains `unknown`.
- EVIDENCE: Source-built compact/JSON q production attacks cover credential, cookie, session, and storage host/path variants with stdout, stderr, and cache absence assertions. Removing only the hostname/path classification call makes `TestRunQProductionEntryRefusesSensitiveURLHostnameAndPathComponentsAcrossFormats` fail with `-count=1`.
- SCOPE: `TASK-260823-17qhsl`; q/grep/m, deterministic extraction, pagination evidence, cache anchoring, transport targeting, and mutation guards are unchanged.

### 0302 — Browser Facade Normalizes Once And Never Projects Raw Transport Detail
- ROOT CAUSE: Revision 4 still split cookie/session/storage classification across field, JSON-key, and URL-query helpers, while transport failures could forward sanitized process stderr; escaped representations therefore bypassed the claimed single boundary.
- DECISION: `EnforceOutbound` now owns one bounded normalization queue, one normalized sensitive-name policy, pre-lossy JSON key/scalar checks, fixed-point URL rescanning, and the sole `clean`/`redacted`/`refused`/`unknown` decision. Browser process stdout/stderr is always discarded from public errors in favor of typed generic failure metadata.
- SAFETY: Source production entries cover cookie/session/storage URL names, escaped schema metadata and transport errors, opaque credential candidates, duplicate adapter/evidence/cache keys, both render formats, cache absence, and exact no-follow scope. Narrowing only the name family, backslash transform, or typed error projection makes the named production tests fail.
- SCOPE: `TASK-260823-17qhsl`; deterministic extraction, pagination evidence, exact target/origin guards, q/grep/m separation, and descriptor-rooted cache traversal remain unchanged.

### 0212 — Revision 4 Anchors Every Browser Facade Boundary Before Decoding Or Traversal
- ROOT CAUSE: The canonical scanner skipped decoded URL query names and common `sk-*` forms, evidence envelopes reached lossy JSON decoding first, and cache scope checks started below a symlinkable ancestor.
- DECISION: Keep one outbound owner: scan names and values, boundedly rescan transformed URLs, validate extractor/advance/mutation evidence before decoding, and open cache data through a descriptor-rooted `os.Root` after refusing every facade-owned symlink component.
- SAFETY: Compact and JSON q paths refuse nested query-name URLs and `sk-proj-*`/`sk-*`; duplicate extractor, advance, and mutation keys produce refusal/unknown; grep cannot follow a symlinked `mac-infra` ancestor outside its physical cache root.
- EVIDENCE: Narrowing production-entry tests first reproduced all four CR revision 3 findings with exit 1, then passed after the centralized fix; installed attack smokes are recorded in the task-scoped revision 4 validation outcome.

### 0145 — Repeated Secret Variants Required One Outbound Decision Owner
- ROOT CAUSE: Schema/list/cache/error checks independently recognized secret shapes, while grep could re-emit raw JSONL after lossy map validation; each per-surface fix left another representation outside the decision boundary.
- DECISION: `internal/browserfacade` now owns one canonical scanner, one `clean`/`redacted`/`refused`/`unknown` state type, and one outbound enforcement call used by q/grep/m rendering, cache read/write, adapter metadata, and transport/CLI errors.
- SAFETY: URL scheme/host/query matching is case-insensitive, every duplicate sensitive query value is redacted, nested/encoded secret URLs and GitHub/GitLab/JWT/Bearer families fail closed, malformed or duplicate-key JSON becomes explicit unknown/refusal, and grep renders canonical validated JSON rather than source bytes.
- EVIDENCE: Production-entry narrowing tests cover uppercase URLs, GitLab tokens, duplicate-key cache shadowing, nested encoding, malformed URLs, direct renderer bypasses, and error-boundary bypasses under `TASK-260823-17qhsl`.

### 0110 — Browser Facade Reports Only Proven Pagination And Revalidates Every Output Surface
- REGRESSION: Revision 1 admitted synthetic Bearer/GitHub-token material and `api_key`/`signature` URL values through schema, list, and cache paths; duplicate pages and bounds were also converted into guessed `hasMore` booleans.
- FIX: One secret-output policy now validates adapter metadata, DOM results, cache writes/reads, and transport errors; common opaque credentials are refused and sensitive URL-key variants are redacted.
- DECISION: Only observed extra records prove `hasMore:true`, and only complete non-paginated reads or explicit `advanced:false` prove `false`; duplicate/stale pages and bounded continuation report `unknown`, while partial envelopes fail with `TRANSPORT_RESPONSE_INVALID`.
- EVIDENCE: Production `mac-browser-site q|grep` entry tests cover narrowed secret classes, cache non-creation, caller/adapter/scan bounds, duplicates, explicit exhaustion, and partial extractor/advance reads under `TASK-260823-17qhsl`.

### 0055 — Browser Site Access Has One Bounded q/grep/m Boundary
- FIX: `mac-browser-site` adds projected/batched `q`, private per-site cached `grep`, and adapter-declared `m` over the existing exact-target Chrome/Safari transports and deterministic extractor.
- DECISION: Pagination is explicit (`none`, `next-page`, page-owned `cursor`, or `infinite-scroll`), adapter and query bounds can only narrow, and unprovable exhaustion reports `unknown`.
- SAFETY: Secret-bearing origins and fields are refused; authorization/token-shaped records fail before cache write; sensitive URL values are redacted; cursor/session state never leaves the page; every mutation requires `--confirm` and has a no-write `--dry-run` path.
- SCOPE: `internal/browserfacade`, `cmd/mac-browser-site`, lifecycle scripts, README, mac-infra skill references, and `TASK-260823-17qhsl` evidence.

### 0018 — Cross-Origin Embedded Apps Can Be Promoted Safely
- FINDING: A useful authenticated application inside a cross-origin iframe may remain unreadable from the host DOM while still bootstrapping successfully as a top-level page in the same Chrome profile.
- DECISION: Promote only a sanitized bootstrap URL into a user-designated disposable background tab, stripping fragments and unknown or secret-bearing query values; then poll an application DOM readiness marker rather than relying on `document.readyState`.
- SAFETY: Keep exact tab and origin guards, never export profile credentials or opaque iframe state, and stop when top-level authentication depends on parent-only state or secret material.
- MILESTONE: The generalized workflow recovered an authenticated embedded conversation UI and enabled bounded deterministic extraction without focusing Chrome.

## 2026-08-23

### 2359 — Heartbeat Health Is Outcome Freshness, Not Process Liveness
- ROOT CAUSE: The legacy watcher treated a live shell as a healthy heartbeat and swallowed Chrome `-1712` Apple Events timeouts; the first unified implementation also let one probe timeout grow to the configured interval, allowing a `20m` check to block for 20 minutes.
- FIX: `internal/browsersession/heartbeat.go` limits each probe to three 10-second attempts with short bounded delays and marks expired last-success outcomes `unavailable` with `stale-outcome`.
- MILESTONE: Installed signed runtime passed a no-focus Chrome read and started `tbank-support` at a 20-minute interval with a real background `ok` outcome.

### 2358 — Repeated Browser Extraction Crosses Open Shadow Roots Deterministically
- FIX: `internal/browserquery` adds a bounded template extractor with allowlisted field sources, projection, predicate, `skip`/`take`, per-field limits, and an explicit capped open-shadow-root traversal.
- SAFETY: URL-bearing attributes and browser-secret sources remain forbidden; live T-Business chat content was written privately and sanitized before inspection.
- STATUS: The deterministic extraction primitive is installed and proven on 28 T-Business chat messages; the broader q/grep/m facade remains tracked by `TASK-260823-17qhsl`.

### 2250 — Background Apple Events Consent Is Per Managed Runtime
- FINDING: Direct guarded Chrome and Safari JavaScript smokes passed, and launchd could read both browser versions, but `execute JavaScript` from a newly pinned LaunchAgent executable waited until the bounded timeout. The existing previously authorized FNS LaunchAgent continued to work. Unified TCC logs recorded `Prompting for access ... by mac-browser-session-*` and `security_exception -67062` while trying to derive identity from the raw Go linker signature.
- FIX: Setup now replaces the linker signature with a complete ad-hoc signature and explicit `works.relux.mac-infra.browser-session` identifier. `heartbeat start` also waits for the first real background outcome and rolls back a failed background preflight instead of reporting a loaded-but-unproven job as running.
- CONSTRAINT: macOS Automation consent for the newly identified background executable still requires human approval. The tool must not bypass that boundary with a foreground proxy, UI scripting, or a non-persistent daemon.
- SAFETY: Throwaway LaunchAgents were stopped and removed, the legacy FNS heartbeat and T-Bank watcher were preserved, and FNS migration was not attempted while the replacement runtime lacked a successful background outcome.
- STATUS: Code, tests, build, setup, installed CLI reads, and direct no-focus browser smokes pass; concurrent heartbeat and FNS migration live gates remain blocked on Automation consent for the managed executable.

### 1840 — Browser Origin Guards Must Be Atomic And Safari Is Window-Scoped
- FINDING: Chrome exposes stable window and tab ids, while Safari exposes stable window ids but no stable tab identity; Safari tab indexes are positional and cannot support an honest exact-tab API.
- DECISION: Chrome operations pin an exact `(window-id, tab-id)` pair. Safari page-context operations pin an exact window, act on its current tab, and require `--origin` so a tab switch fails closed.
- FIX: The expected-origin comparison and caller payload now execute in one injected page-context evaluation. Empty, malformed, or sentinel-free automation responses are refusals rather than inferred matches.
- SAFETY: Named heartbeats share one managed namespace, use content-addressed executable copies, log no page titles/text, and never re-find a drifted target.
- SCOPE: `internal/browsersession`, `internal/chromectl`, `internal/safarictl`, both browser CLIs, lifecycle scripts, README, and mac-infra skill references.

### 0028 — Repeated DOM Extraction Must Be Deterministic
- DECISION: The future agent-facing browser facade accepts an agent-selected element template plus a predicate or `skip`/`take`; a pure function performs matching, field extraction, filtering, and pagination.
- DECISION: Agent cognition chooses the template and query parameters only; it must not interpret or normalize every repeated marketplace/list item individually.
- FINDING: This GraphQL-like projection boundary keeps large repeated DOM lists out of agent context and makes extraction reproducible across runs.
- SCOPE: Follow-up `TASK-260823-17qhsl`; transport remains `mac-chrome-session` or `mac-safari-session`.

### 0014 — Background Browser Session Heartbeats Proven
- MILESTONE: Concurrent exact-tab heartbeats kept authenticated FNS and T-Bank Chrome sessions usable while unrelated work continued.
- FINDING: Periodic page-context pointer and harmless Shift events through `execute targetTab javascript` preserve activity without activating Chrome or selecting the tab.
- DECISION: Chrome automation has silent and visible/handoff modes; silent is default, visible focus requires an explicit user request.
- STATUS: The low-level pattern is documented and installed; a guarded `mac-chrome-session` lifecycle CLI remains a useful follow-up.

## 2026-08-22

### 2243 — Authenticated Chrome Apple Events Verified
- MILESTONE: `TASK-260822-1db1bg` documented no-focus DOM inspection and interaction for exact authenticated Google Chrome window/tab IDs.
- FINDING: Chrome 151 executes bounded page JavaScript after the user enables `View -> Developer -> Allow JavaScript from Apple Events`; a live `business.tbank.ru` title/origin smoke passed without activation.
- SAFETY: Chrome retains cookies, browser storage, authorization headers, and tokens; raw Apple Events output stays private and only sanitized bounded results are inspected.
- SCOPE: `agents/skills/mac-infra/SKILL.md`, `agents/skills/mac-infra/references/chrome-session.md`, and `README.md`.

## 2026-08-03

### 1114 — Privacy-Safe Document Intake Installed
- MILESTONE: `TASK-260803-22l53w` added and installed `mac-document-sanitize` plus reusable `internal/docsanitize` for TXT/Markdown/JSON/CSV/TSV/HTML/RTF/DOC/DOCX/PDF/XLSX intake.
- DECISION: Originals stay read-only; raw extracted text stays in memory; default `0600` artifacts use content hashes instead of source filenames; reports store categories/counts but never matched values.
- FIX: Main `agents/skills/mac-infra/SKILL.md` shrank from 620 to 486 lines by moving Safari and audio-sweep details to lazy references.
- STATUS: Full tests, targeted race tests, vet, setup/install, skill validation, synthetic multi-format smokes, and three local Word-document smokes passed.

### 1114 — Phone Redaction Must Precede SNILS
- ROOT CAUSE: An unlabelled Russian `+7` phone also matched the generic 11-digit SNILS shape when SNILS ran first, hiding the value but misreporting its category.
- FIX: Phone detection now precedes SNILS detection in `internal/docsanitize/sanitize.go`; regression coverage verifies `[PHONE_n]` classification.

## 2026-08-02

### 1815 — Idle Lock Prevention Split Into Independent Policies
- DECISION: `TASK-260802-19m3qg` keeps system sleep, display sleep, and idle-lock prevention as separate commands; there is no combined all-policy mutation.
- SAFETY: Idle-lock prevention does not call `sysadminctl -screenLock off`; manual Lock Screen and the immediate password policy remain unchanged.
- FIX: Display prevention uses a persistent current-user `/usr/bin/caffeinate -d` LaunchAgent without rewriting `pmset`; `idle-lock-prevention` captures and restores the current user's ByHost `idleTime` preference to control the automatic screen-saver lock trigger.
- SCOPE: `internal/maccore`, `cmd/mac-infra-core`, `README.md`, `agents/skills/mac-infra/SKILL.md`, `scripts/setup.sh`, and installed-command verification.

## 2026-07-19

### 1742 — System-Wide Sleep Prevention Contract Resolved
- DECISION: `TASK-260719-cigkb7` uses one global `SleepDisabled` state with `applies_to: AC,battery`; no per-profile `disablesleep` values are invented.
- FIX: Added fixed root-daemon actions for `/usr/bin/pmset -a disablesleep 1|0`, strict `/usr/bin/pmset -g` parsing, and `mac-infra-core sleep-prevention enable|disable|status`.
- SCOPE: `internal/maccore`, `cmd/mac-infra-core`, `README.md`, `agents/skills/mac-infra/SKILL.md`, and `scripts/setup.sh`.
- STATUS: The provisional 1725 blocker is superseded by the revised system-wide contract. Tests, vet, build, setup, installed read-only status, and installed-skill match passed; reinstall the privileged daemon before live mutations.

### 1725 — SleepDisabled Is System-Wide
- FINDING: `/usr/bin/pmset -g` exposes one system-wide `SleepDisabled`; `/usr/bin/pmset -g custom` exposes AC/battery profiles without that key.
- FINDING: Apple `PowerManagement` source writes `disablesleep` through `IOPMSetSystemPowerSetting`, outside per-source preferences (`pmset/pmset.m:5813`, `pmset/pmset.m:802`).
- BLOCKED: `TASK-260719-cigkb7` requires per-source and inconsistent `disablesleep` states that the platform cannot represent.
- DECISION: Recommend one system-wide `enabled`/`disabled`/`unavailable` status; do not infer it from unrelated `sleep` timers.

## 2026-06-15

### 1632 - Safari Browser Session Harvest
- DECISION: Authenticated browser harvest uses Safari Apple Events and page-context `fetch(..., { credentials: "include" })`; cookies and browser storage stay inside Safari.
- FIX: Added `mac-safari-session` CLI plus reusable `internal/safarictl` package for background open, JS permission check, DOM snapshot, guarded JS, and chunked authenticated file fetch.
- FIX: Guard rejects obvious secret reads: `document.cookie`, `cookieStore`, `localStorage`, and `sessionStorage`; response metadata drops sensitive headers.
- SCOPE: `cmd/mac-safari-session`, `internal/safarictl`, `README.md`, `agents/skills/mac-infra/SKILL.md`, `scripts/setup.sh`, `scripts/deinit.sh`.
- STATUS: Verified with `go test ./...`, `./scripts/setup.sh`, installed CLI help, cookie guard smoke, live `mac-safari-session check-js`, and `task-board validate`.

## 2026-06-12

### 1337 - AnyConnect Socket Filter Cleanup
- FINDING: Cisco AnyConnect can report `Disconnected` while `com.cisco.anyconnect.macos.acsockext` remains activated/enabled and resident around `869MB`.
- FIX: Added `mac-load-profile anyconnect` for read-only VPN state, system extension, `acsockext`, and `vpnagentd` diagnostics.
- FIX: Added `mac-infra-core anyconnect-cleanup` dry-run plus allowlisted `cleanup_anyconnect` apply action guarded by `vpn status == Disconnected`.
- SCOPE: `internal/anyconnect`, `cmd/mac-load-profile`, `cmd/mac-infra-core`, `internal/maccore`, `README.md`, `agents/skills/mac-infra/SKILL.md`.
- STATUS: User-level setup installed updated CLI/skill; root daemon reinstall is pending interactive sudo before `--apply` can run live.

## 2026-05-21

### 1121 - CoreSimulator Runtime Cleanup
- ROOT CAUSE: Xcode stale simulator entries came from unsupported legacy `.simruntime` bundles under `/Library/Developer/CoreSimulator/Profiles/Runtimes`, not from unavailable device records.
- FIX: Removed iOS 13.5, 14.2, 14.5, and 15.0 runtimes with `xcrun simctl runtime delete`; `simctl list runtimes` now shows only supported installed runtimes.
- FIX: Added `mac-cleanup xcode-runtimes` to detect `unavailable` + `deletable` runtimes and delete them only with explicit `--delete`.
- SCOPE: `cmd/mac-cleanup/main.go`, `internal/simcleanup/runtime.go`, `agents/skills/mac-infra/SKILL.md`, `README.md`.
- STATUS: Verified with `go test ./...`, `scripts/setup.sh`, and installed `mac-cleanup xcode-runtimes`.

## 2026-05-19

### 1600 - Cleanup Planner Test Roots
- FINDING: macOS `t.TempDir()` resolves under `/var/folders`, and cleanup root policy intentionally refuses `/var` descendants.
- DECISION: Cleanup planner/CLI tests use repo-local temporary directories under the checkout so fixtures exercise allowed user-owned child roots without weakening production safety rules.
- SCOPE: `internal/cleanup/planner_test.go`, `cmd/mac-cleanup/main_test.go`.

### 1557 - Disk Profile CLI Text Contract
- FIX: `internal/diskprofile/render.go` owns concise tabular text rendering for scan/top/explain output.
- FIX: `cmd/mac-disk-profile top` treats `--files` and `--dirs` as selectors; absent selectors renders both tables.
- ANOMALY: Sandboxed Go commands need task-scoped `GOCACHE/GOPATH`; default `~/Library/Caches/go-build` is not writable.
- STATUS: Verified with `go test ./...`, `go vet ./...`, `go build ./...`, and `gofmt -l cmd internal`.

### 1547 - Cleanup Plan Apply Contract
- DECISION: `internal/cleanup.Plan` schema v1 includes `categoryPolicyVersion`, `hashInputs`, `generatedAt`, `staleAfterSeconds`, root realpath, candidate identity, risk/default flags, sizes, apply contract, and `planHash`.
- DECISION: `clean --apply` v1 requires `--plan PATH`; direct category apply is explicitly unsupported until a future rescan-and-confirm flow exists.
- DECISION: Apply preflight refuses stale plans after 24h, hash mismatch, selected out-of-scope candidates, changed candidate identity, symlink swaps, out-of-root realpaths, and ownership mismatches before any deletion code can run.
- SCOPE: Contract and revalidation helpers only; no Trash/permanent deletion implementation.

### 1547 - Disk Scan Resource Controls
- DECISION: `internal/diskprofile` applies default generated-tree excludes by default; `--exclude` adds patterns; `--no-default-excludes` opts back into generated trees.
- DECISION: Top dirs/files are retained with bounded lists; JSON hierarchy retention is capped by `MaxRetainedEntries` without stopping byte accounting.
- FIX: Context cancellation now records `canceled` scan errors and returns a partial result with the context error.
- SCOPE: `internal/diskprofile` resource controls and `cmd/mac-disk-profile` flags.

### 1528 - Disk Profile Scan Model Contract
- DECISION: `internal/diskprofile` uses `os.Lstat` only, never follows symlinks, and records symlink skips as non-fatal `ScanError` entries.
- DECISION: Logical bytes are lstat apparent size; disk bytes are best-effort `st_blocks * 512`; hard links are de-duped by `(device,inode)`.
- DECISION: Scan JSON is schema-versioned and written with restrictive artifact permissions: created dirs `0700`, JSON files `0600`.
- SCOPE: Read-only disk profiler model and `cmd/mac-disk-profile`; cleanup executor/apply semantics unchanged.

### 1528 - Cleanup Category Policy Boundary
- DECISION: `internal/cleanup/policy.go` separates default-selected safe generated data from review-only user/risky data and v1 out-of-scope categories.
- DECISION: External volume roots are refused; child paths under `/Volumes/<name>/...` require explicit target selection plus ownership, symlink, and realpath containment checks.
- SCOPE: Category policy only; no deletion executor, scanner traversal, docs, setup, or disk profile changes.

### 1527 - Cleanup and Disk Work Package Decomposition
- FINDING: Board already captured architect-review blockers for plan/apply, Trash semantics, disk accounting, and resource controls.
- FINDING: Two implementation gaps remained: disk extension/type summaries and a non-mutating cleanup apply revalidation guard layer.
- DECISION: Added `TASK-260519-2lvhmz` for disk extension/type summaries before JSON artifacts.
- DECISION: Added `TASK-260519-3m5108` to split TOCTOU/revalidation guards from destructive Trash execution.
- DECISION: Linked docs/integration after category story so README/skill describe final category behavior, not just core CLIs.
