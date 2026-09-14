# STORY-260915-3r0ys5: keyvault-module-secure-enclave-signer

## Description
keyvault module \u2014 the workstation as the HSM stand-in (owner 2026-09-15). P-256 keys in Secure Enclave / Keychain, non-exportable, signing through SecKey. Commands: `keyvault init <label>` (create pair, ACL bound to the user/binary), `list`, `pub <label>` (SPKI DER/PEM), `sign <label>` (DER ECDSA over a digest, low-S normalised; raw r\u2016s option), `verify` (by label or SPKI), `rotate`, `delete` (confirmed). Consumer: kvctl (jc-keyvault) Signer backend `macos-keychain` for the test PKI root/intermediates so no private key ever sits in a repo. Tests with a throwaway label only; never touch existing Keychain items; document the ACL prompts the user will see.

## Scope
Land the accepted Story candidate: T1 key store + record model v2 (1a150bd), T2 sign/verify (39131c7), T3 signer contract for kvctl + docs (6c25ca3), all checkpointed and signed on task-board/story/STORY-260915-3r0ys5. Integration run: task-board worktree integrate STORY-260915-3r0ys5 from the control root; then the Story reaches done. Commit dating per owner policy (backdated to previous day after 20:00 MSK) where the tool allows; signing via the configured relux-works SSH key.

## Acceptance Criteria
worktree integrate lands exactly the checkpointed tree as one signed squash commit on main with no other change; the board-only commit follows; every leaf (2mf19o, nl5may, 2ny9kd) and the Story are done; go vet/build/test -count=1 ./... green on the landed main; mac-keyvault --json list shows no test-label items; main pushed to origin fast-forward.
