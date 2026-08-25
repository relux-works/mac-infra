# TASK-260826-10ftog Developer Revision 8 Outcome

## Result

Revision 8 closes the independent-review production-call-site evidence gap for guarded Chrome native upload. `TestChromeAXUploadProductionPathRefusesUnreadableSheetSequences` now calls the real `macChromeAXUploadFiles` entry and intercepts only OS-facing AppKit, Accessibility, sleep, and keyboard dependencies. The entry itself selects both production sheet waits.

No live Chrome session, tab, page, Accessibility tree, chooser, cookie, storage, authorization material, local source content, or browser secret was contacted during development or validation. The compiled harness posts no real keyboard events.

## Rework

- Replaced the helper-level AXSheets sequence harness with a compiled production-entry harness.
- Appearance attacks cover AX read error, null value, and wrong type followed by enough valid chooser evidence to reach keyboard interaction if the production call site retries unreadable evidence. Correct behavior refuses at the first unknown snapshot with zero keyboard events.
- Closure attack supplies a later proven empty snapshot and requires the production entry to preserve the earlier unreadable refusal instead of attesting successful closure.
- Valid empty-to-one appearance and retained-one-to-empty closure controls prove that retryable states remain admitted.
- Added an append-only `LOGBOOK.md` correction recording that revision 7's helper harness did not prove the production call site.
- Preserved the Story worktree's reverse/stale index and unrelated dirty state. No files were staged or committed.

## Negative Evidence

| Attack | Exit | Result |
| --- | ---: | --- |
| Production appearance call site routed through an unreadable-retrying wait | 1 (expected red) | Named test failed with harness exit `21`; a permissive unreadable-to-one path cannot reach chooser keys or success unnoticed. |
| Production closure call site routed through an unreadable-retrying wait | 1 (expected red) | Named test failed with harness exit `24`; unreadable-to-empty cannot become successful chooser closure. |

Both mutants were applied only after copying `internal/chromectl/ax_darwin.m` to a task-scoped backup. Production source was restored byte-for-byte (`SHA-256 cf7cbd08b7c50c65bb46f000446ef26b9fb53cb84aa29a727f4d6b6400bc22bf`) before every green gate. No `Permissive` symbol remains in production.

## Validation Evidence

| Gate | Exit | Evidence |
| --- | ---: | --- |
| Production-entry AXSheets gate, restored source | 0 | `TASK-260826-10ftog_focused-production-entry-01.log` |
| Focused packages: `go test -count=1 ./internal/chromectl ./cmd/mac-chrome-session` | 0 | `internal/chromectl` 59.232s; CLI 27.856s |
| Full uncached suite: `go test -count=1 ./...` | 0 | slowest package `internal/chromectl` 98.720s |
| `go vet ./...` | 0 | no diagnostics |
| `go build ./...` | 0 | no diagnostics |
| `gofmt` empty assertion for Chrome CLI/chromectl | 0 | no unformatted files |
| `git diff HEAD --check` | 0 | no whitespace errors |
| `./scripts/setup.sh` | 0 | tests, builds, signing, binary install, and skill install passed |
| Installed `mac-chrome-session help` and `upload` presence | 0 | installed help exposes `upload` |
| Installed strict code-sign verification | 0 | `/usr/bin/codesign --verify --strict` |
| Installed binary unreadable-sheet marker | 0 | `file-chooser-unreadable` present |
| Installed skill and Chrome reference parity | 0 | source and installed copies match byte-for-byte |

The two expected-red commands are intentionally reported as failing. They are the narrowing evidence that the production entry, rather than a separately invoked helper, owns the refusal.
