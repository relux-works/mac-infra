# TASK-260915-2mf19o — integration run for CR-TASK-260915-2mf19o-7 (rev 7): BLOCKED on commit signing

Run: RUN-260915-ee0d1e (developer/implementer, integration binding)
Worktree: .temp/STORY-260915-3r0ys5/worktree, branch task-board/story/STORY-260915-3r0ys5
Branch tip = checkpoint_oid = base_oid = f9ec756b123ea66a02545369ed007d9ddd8c5540
Accepted candidate tree: e322b08ef1beddb79717a4d7a94b817a606e6633
Working tree (read-tree HEAD + add -A + write-tree) = e322b08e… — identical to the accepted candidate. Nothing drifted.

## Fresh verification on the candidate tree (run standalone, real exit codes)

| Command | Exit | Log |
| --- | ---: | --- |
| `go vet ./...` | 0 | .temp/TASK-260915-2mf19o/integration-vet-01.log |
| `go build ./...` | 0 | .temp/TASK-260915-2mf19o/integration-build-01.log |
| `go test -count=1 ./...` | 0 | .temp/TASK-260915-2mf19o/integration-test-01.log (all packages ok, incl. internal/keyvault 4.5s) |

## Bound integration command

`task-board worktree checkpoint TASK-260915-2mf19o --json` → process exit 0, JSON error envelope:

```
change_request_checkpoint_conflict: creating the internal checkpoint commit
(candidate_tree=e322b08ef1beddb79717a4d7a94b817a606e6633, element_id=TASK-260915-2mf19o)
```

No ref was moved (branch tip still f9ec756). Re-ran 3x, same result.

## Root cause (traced with a git shim on PATH)

The last git call task-board makes is:

```
git commit-tree -S e322b08e… -p f9ec756b… -m "TASK-260915-2mf19o: … Change-Request: CR-TASK-260915-2mf19o-7 revision 7"
```

`-S` = mandatory commit signing (the binary also carries `commit.gpgsign=true`, `signing_failed`,
"replaying %s onto %s with signing failed; no ref was moved"). On this machine that fails:

```
gpg: skipped "alexis <alexis@relux.works>": No secret key
gpg: signing failed: No secret key
```

Evidence of the environment:
- `git config --get user.signingkey` / `gpg.format` / `commit.gpgsign` → all unset (global, relux-works include, repo, worktree)
- `gpg --list-secret-keys` → empty; ~/.gnupg has no key material
- every commit on `main` and on the older story branch shows `%G? = N` (unsigned), so signing has never been configured here; the checkpoint command in task-board 3c568c7b (built 2026-09-14) requires it.
- task-board reports the error as `checkpoint_conflict` rather than `signing_failed`; that misclassification is a task-board bug worth a note in its own repo (the CAS did not conflict, the commit object creation failed).

Unsigned `git commit-tree` (no -S) of the same tree succeeds → the tree, parent, and identity are fine; only the signature is missing.

## What I did NOT do

- Did not generate a GPG key or set `user.signingkey`/`gpg.format`/`commit.gpgsign` — that is a durable identity decision on the owner's machine and the policy forbids inventing a signing identity.
- Did not commit, reset, or move any ref. The two probe `commit-tree` objects (5b187e05 unsigned, 06c145a9 ssh-signed) are dangling and unreferenced; git gc will drop them.
- Did not set the board status (assignment: keep `integrating`; integration transaction owns `done`).

## Probe that proves the fastest fix works

Without touching any config, a one-shot override signs successfully with the existing GitHub SSH key:

```
git -c gpg.format=ssh -c user.signingkey=$HOME/.ssh/alexis_github.pub commit-tree -S <tree> -p HEAD -m probe
→ 06c145a9…  (object contains an SSH SIGNATURE block)
```

## Human decision needed (exact)

Pick the git signing identity for relux-works commits on this machine, then re-run the checkpoint. Options:

1. **SSH signing with the existing GitHub key (recommended, zero new key material):**
   ```
   git config --file ~/.gitconfig-relux-works gpg.format ssh
   git config --file ~/.gitconfig-relux-works user.signingkey ~/.ssh/alexis_github.pub
   git config --file ~/.gitconfig-relux-works commit.gpgsign true
   ```
   and register `~/.ssh/alexis_github.pub` as a *Signing key* in GitHub → Settings → SSH and GPG keys
   (an auth key is not automatically a signing key; without registration GitHub shows "Unverified" but the checkpoint itself will succeed).
   Note the key's comment is `alexis-ag@mail.ru`; GitHub verifies by key, not comment, so that is cosmetic.
2. **GPG:** import/generate a GPG key for `alexis <alexis@relux.works>`, set `user.signingkey`, upload the public key to GitHub.
3. Relax the task-board checkpoint signing requirement (task-board repo change) — not recommended; it contradicts the "every agent-created commit is signed" policy.

After the config lands, the integration re-run is just:
```
task-board worktree checkpoint TASK-260915-2mf19o --json
```
(working tree already equals the accepted candidate; no rework needed).
