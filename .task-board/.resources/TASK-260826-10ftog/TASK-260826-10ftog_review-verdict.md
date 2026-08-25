# TASK-260826-10ftog Review Verdict — CR Revision 8

## Verdict

**Accepted.**

Change Request `CR-TASK-260826-10ftog-8`, revision `8`, candidate tree
`6b706eaa12c43601e3e8d5858fadb1984489a135` satisfies the task acceptance
criteria and closes revision 7's production-call-site evidence gap. No code was
modified by this reviewer and no live Chrome session, tab, page, Accessibility
tree, file chooser, cookie, storage, browser secret, or local file content was
contacted.

The attached patch materialized from the board hashes to
`c18de3e381e1dfda376619d7e826cce7f8743f38a2478822025555223db26154`, matching
the handed-off revision. The 54-path snapshot is the accumulated Story-final
delta; revision 7 to revision 8 changes only `LOGBOOK.md` and
`internal/chromectl/ax_darwin_test.go`. The four dropped `.task-board` paths are
control-plane diagnostics excluded by Change Request construction and do not
alter the product candidate.

## Gate-defeat evidence

The repaired `TestChromeAXUploadProductionPathRefusesUnreadableSheetSequences`
compiles the production Objective-C source and enters through the real
`macChromeAXUploadFiles` function. Only OS-facing AppKit, Accessibility, sleep,
and keyboard dependencies are intercepted; the production entry chooses the
appearance and closure waits.

- Restored candidate: the named production-entry test passed uncached.
- Appearance narrowing mutant: only the production call site was routed through
  a wait that retries `MacChromeAXFileChooserUnreadable`. The named test failed
  with harness exit `21`, proving unreadable-to-one cannot reach chooser keys.
- Closure narrowing mutant: only the production closure call site was routed
  through a wait that retries unreadable evidence. The named test failed with
  harness exit `24`, proving unreadable-to-empty cannot attest successful
  closure.
- Both mutants were isolated under `.temp/`; the immutable candidate remained
  unchanged.

This directly defeats the revision 7 negative shapes **check present but
uncalled from production** and **bypass path around the check** on both protected
surfaces. The test also retains admitted empty-to-one and one-to-empty controls,
so the evidence is a narrowing proof rather than a delete-only proof.

## Independent validation

| Gate | Result |
| --- | --- |
| `git diff --check <base> <candidate>` | pass |
| Restored production-entry AXSheets test | pass; `1.483s` package time |
| `go test -count=1 ./internal/chromectl ./cmd/mac-chrome-session` | pass; `84.246s` / `44.229s` |
| `go test -count=1 ./...` | pass; slowest `internal/chromectl` `107.008s` |
| `go vet ./...` | pass |
| `go build ./...` | pass |
| Installed `mac-chrome-session help` | pass; exposes explicit authorized `upload` command |
| Installed strict code signature | pass |
| Installed binary unreadable-sheet marker | pass |
| Installed mac-infra skill and Chrome reference parity | pass; byte-identical to candidate |

The producer's revision 8 outcome records a successful `./scripts/setup.sh`,
sign/install, help, marker, and skill-parity run against the restored candidate.
The reviewer did not repeat the mutating setup/install step; its read-only
installed checks above reproduce the resulting contract. One initial reviewer
wrapper used zsh's read-only variable name `status` after the test command; the
test was rerun with a task-specific variable and passed. That wrapper error was
not treated as product evidence.

## Review result

No findings remain. The exact-target/origin/authorization gates, bounded regular
file staging, DOM and native chooser drift refusals, privacy-safe output, help
and installed skill contract, and production-path negative evidence are covered
by the candidate and its passing test suite. Accept revision 8 and hand it to
the Orchestrator for checkpoint/integration; this reviewer supplies no
`commit_ack`.
