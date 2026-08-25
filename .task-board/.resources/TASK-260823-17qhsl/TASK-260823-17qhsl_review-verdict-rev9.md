# TASK-260823-17qhsl Review Verdict — CR Revision 9

Date: 2026-08-26 MSK

## Verdict

- **Accepted**. Record acceptance with `accept_cr` for revision 9.
- No implementation finding remains. No external blocker, human-only decision,
  or Stop-The-Line boundary exists.

## Empty Repository Delta Is Correct

Revision 9 has `repository_delta=empty`, and that is the correct outcome for
this recovery leaf. Revision 8 became stale behind later Story checkpoints; the
revision-9 producer's deliverable was to revalidate the facade at the current
Story checkpoint, not to invent another source change after the revision-7
final-cache-symlink defect had already been fixed in the current tree.

Independent provenance checks established:

- base commit: `513250c427ac115fadc7b9239e6bd594c4e4e88e`;
- base tree and candidate tree:
  `4528b2c757e92c663ea37f47e5bc28a8aaaf4dd7`;
- exact base-to-candidate diff: zero paths and zero bytes;
- board patch: zero bytes, SHA-256
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`,
  byte-identical to a fresh exact-diff export;
- all 37 historical facade candidate paths match the current managed worktree
  by content and mode; mismatch count is zero;
- task-owned `cmd/mac-browser-site`, `internal/browserfacade`,
  `internal/browserquery`, and facade reference paths are clean relative to
  the candidate.

The managed index still contains unrelated shared-Story staged state, while
the working files themselves equal `HEAD`. Review was therefore repeated from
a clean archive of the exact candidate tree so index state could not become
proxy evidence.

## Gate-Defeat Evidence

The exact candidate and freshly installed production entry points were driven,
not only helper APIs.

| Check | Result |
| --- | --- |
| Clean exact-candidate `go test -count=1 ./internal/browserquery ./internal/browserfacade ./cmd/mac-browser-site` | Pass; deterministic extractor, facade owner, and production CLI packages green. |
| Exact-candidate source-built `grep --file` final symlink, compact / JSON | Inner exits 1 / 1 with `CACHE_SCOPE_REFUSED`; marker and physical path absent; external file and symlink preserved. |
| Fresh exact-candidate setup/install | Pass; installation completed from the clean candidate archive, attacks ran, then current worktree installation was restored successfully. |
| Exact-installed final symlink, compact / JSON | Inner exits 1 / 1 with typed refusal, no disclosure, external target preserved. |
| Exact-installed hostname/path secret matrix | 22/22 attacks returned typed refusal/unknown; stdout, stderr, and cache disclosure absent. |
| Exact-installed q/grep/m regression matrix | Nested and duplicate evidence, raw transport errors, duplicate cache keys, ancestor symlink, target/origin, mutation refusal/preview/confirm, and pagination-bound `unknown` all behaved as required. |
| Installed schema secret adapter, compact / JSON | Exits 2 / 2 with typed refusal/unknown; Bearer, GitHub/GitLab, project-token, key, and signature shapes absent from stdout/stderr. |
| Narrow final-symlink refusal back to `continue` in an isolated candidate copy; run named production test with `-count=1` | Expected red, exit 1. Both compact and JSON falsely returned success/empty, so the production test defeats the narrowing mutant. Original candidate remained untouched. |

The installed regression matrix also independently reproduced the compactness
evidence: 893-byte raw extractor output versus 132-byte projected compact
output, an 85.2% byte reduction (estimated 223 versus 33 output tokens).

## Architecture Inspection

- `EnforceOutbound` remains the sole exported secret classification owner with
  one `clean | redacted | refused | unknown` decision vocabulary.
- Adapter decoding, browser records, cache write/read, canonical grep records,
  typed transport errors, and final buffered compact/JSON renderers reach that
  central owner; `WriteOutbound` prevents partial renderer output.
- URL hostname and every decoded path component use the shared normalized-name
  and credential policy. Nested encoding, duplicate keys, malformed input, and
  normalization exhaustion fail closed.
- Cache access is descriptor-rooted through `os.Root`; attacker-controlled
  components are no-follow, and an explicitly requested final symlink is a
  refusal rather than a false empty result.
- Deterministic extraction, bounded tri-state pagination, q/grep/m separation,
  exact target/origin guards, and mutation preview/confirmation remain intact.

## Validation

| Command | Result |
| --- | --- |
| `go test -count=1 ./...` | Pass; full uncached worktree suite. |
| `go vet ./...` | Pass. |
| `go build ./...` | Pass. |
| `gofmt -l cmd internal scripts` | Empty. |
| `git diff --check`, `git diff --cached --check`, `git diff HEAD --check` | Pass. |
| `task-board validate` | Pass. |
| `./scripts/setup.sh` | Pass; build/sign/install and skill sync complete. |
| Installed binary, skill, and facade reference parity after restoration | Byte-identical to the managed worktree installation targets. |

The first standalone source-build wrapper used zsh's read-only variable name
`status` after the build command and exited 1 for that wrapper error. The build
was rerun immediately with a safe variable name and exited 0; no product source
was changed.

