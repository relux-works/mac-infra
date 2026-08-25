# BUG-260825-2pn2en — reviewer verdict: ACCEPTED

Change Request `CR-BUG-260825-2pn2en-1` revision 1.
Base `4a8d2922d46aae3382d3a24acb9b52cb22dfdfa7` → candidate `cdba3556995d0f7456f04e1f81ec864324cb8015`.

## Candidate identity

All six changed paths in the working tree hash-match the candidate tree object
(`git hash-object` vs `git rev-parse <tree>:<path>`), so everything below was
measured against the exact reviewable delta and not a drifted checkout. The
diagnostic path `.task-board/.board-write-ledger.json` is untracked in the
worktree and absent from the candidate; the control plane is not carried.
`internal/` has zero changed files, so the exact window/tab targeting, the
in-page origin guard, and the browser-secret token refusal are literally the
same production code as at base.

## Gates attacked, not read

Seven mutants applied to `cmd/mac-chrome-session/main.go`, each reverted and
the file re-verified byte-for-byte (`66b7ae43...`) after every run.

| # | Mutant | Shipped suite | Verdict |
| --- | --- | --- | --- |
| M1 | Delete the blank `--out` gate in `runJS` | FAIL `.../blank-path` (code=1 want=2) | killed |
| M2 | Narrow both whitespace checks to zero-length-only (producer's claimed mutant) | FAIL blank-path + directory-target + unwritable; `marker` proves dispatch | killed |
| M3 | Drop `fs.Visit` detection, derive `outRequested` from the trimmed value | FAIL 3 cases; page payload reached stdout and osascript was dispatched | killed |
| M4 | Preflight failure no longer returns (falls through with `output = nil`) | FAIL directory-target + unwritable; `marker` proves dispatch | killed |
| M5 | `Chmod(0o600)` → `0o644` | FAIL both parity subtests (`artifact mode=0644`) | killed |
| M6 | Duplicate `result` to stdout alongside the artifact | FAIL parity subtests + publish-failure test | killed |
| M7 | Remove `defer output.Abort()` | PASS | **survived** — see findings |

M2/M3/M4 are the load-bearing ones: each one is a real leak shape (page content
on stdout, or browser dispatch on a path that must fail closed), and each is
caught by a named production-entry test through `run()`, not by a helper unit
test. The production call site is `runJS` → `prepareRunJSOutput`
(`= prepareAtomicOutputArtifact`) → `RunJavaScript` → `Commit`.

## The stubbed negative was verified against the real helper

The shipped `unwritable` case swaps `prepareRunJSOutput` for a stub, so on its
own it proves only the error branch, not the helper. I ran throwaway probe tests
(added, run, deleted; tree re-verified clean) driving `run()` with the real
`prepareAtomicOutputArtifact` and a fake `osascript` that touches a dispatch
marker:

| Real filesystem case | Exit | Dispatch marker | stdout | Artifact |
| --- | ---: | --- | --- | --- |
| out under a `0500` directory | 1 | absent | empty | none |
| out whose parent is a regular file | 1 | absent | empty | none |
| out nested under a `0500` directory (MkdirAll path) | 1 | absent | empty | none |
| out is a symlink to an existing file | 0 | n/a | `out: PATH` only | symlink replaced, **victim file untouched** |
| origin-mismatch refusal with `--out` | 1 | n/a | empty | none, **no temp leftover** |

The symlink case matters: `os.Lstat` + `os.Rename` means the tool never follows
a symlink and never writes through one into a third-party file. That is the
correct choice.

## Installed-artifact smoke

Run against this worktree's own signed `bin/mac-chrome-session`
(`codesign --verify --strict` ok), driving the real binary:

- `run-js --help` exposes `-script`, `-file`, `-out` with the atomic/`0600`/
  `instead of stdout` wording; identical to a fresh source build's help.
- `--out '  '` → exit 2, "requires a non-empty --out PATH", no dispatch.
- `--out` with no value → exit 2, flag error.
- `--out` under an unwritable directory → exit 1 at preflight, no dispatch.
- `--script` + `--file` together, and neither → exit 2, no artifact.
- `--script 'localStorage.getItem("x")' --out PATH` → exit 1 on the blocked
  token, no artifact, no `.mac-chrome-session-run-js-*` leftover anywhere.

No live browser dispatch was performed; every smoke exercises a path that fails
before Apple Events, per the no-focus policy.

## Suites, lint, docs

- `go test -count=1 ./cmd/mac-chrome-session` — ok.
- `go test -count=1 ./...` — ok, no FAIL lines.
- `go vet ./cmd/mac-chrome-session` — exit 0. `gofmt -l cmd/mac-chrome-session` — empty.
- Source vs installed skill: `cmp` clean for `SKILL.md` and
  `references/chrome-session.md`.
- README, `SKILL.md`, `references/chrome-session.md`, top-level help, and
  `run-js` flag help all state the same `--script`/`--file` + optional atomic
  `0600 --out` contract, including the no-stdout-fallback rule.

## Findings (non-blocking)

1. **`defer output.Abort()` is untested (M7 survived).** Removing it leaves an
   orphaned zero-byte `0600` temp file in the destination directory on every
   guard refusal or dispatch error. My probe proves the cleanup currently works;
   it is only the regression fence that is missing. No page content is in that
   file, so this is hygiene, not a privacy gate. Worth a one-line assertion in
   `TestRunJSProductionEntryDoesNotPublishOutputOnOriginRefusal` (`os.ReadDir`
   on the parent must be empty) in a follow-up.
2. **A symlink-to-directory bypasses the "path is a directory" refusal.**
   `os.Lstat` reports the symlink, not the directory, so `--out somedirlink`
   proceeds and `os.Rename` replaces the symlink with a regular result file
   instead of refusing. Reproduced: exit 0, `dirlink` becomes a file, the real
   directory is untouched. No traversal and no write into the directory, so this
   is a small consistency gap, not a security hole. Using `os.Stat` for the
   is-directory test only (keeping `Rename`'s non-following publish) would close
   it without weakening the symlink safety above.
3. **Environment race, not a code defect.** Mid-review, at 20:26, a concurrent
   run for `BUG-260825-2qoq0a` repointed `~/.local/bin/mac-chrome-session` at
   its own worktree, and the global `mac-chrome-session` briefly answered
   `flag provided but not defined: -out` again. Parallel story worktrees running
   `scripts/setup.sh` contend over the same `~/.local/bin` symlinks, so any
   "installed CLI" evidence in this story is only true at the instant it was
   taken. My smokes above were re-run against this worktree's absolute
   `bin/` path for that reason. The orchestrator should re-run `setup.sh` from
   the integrated trunk checkout after merge.

## Verdict

Accepted. Every acceptance criterion is met and the fail-closed behavior is
mutation-verified through the real production entry point and the real signed
binary, not just read. The two code findings are follow-up polish and neither
lets the gate admit what it must reject.
