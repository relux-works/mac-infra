# TASK-261015-3vhkha: keyvault-ssh-agent-and-migration-runbook

## Description
Implement selected keyvault P-256 identities via OpenSSH agent on private 0600 socket, keychain-only signing, refuse add/remove/export/lock, optional per-use confirmation, user LaunchAgent support, Git SSH transport/signing interoperability, golden OpenSSH signature verification and refusal controls. Write migration runbook, never execute it or touch ~/.ssh/GitHub keys. FIRST priority.

## Scope
(define task scope)

## Acceptance Criteria
ssh-keygen -Y verify golden/control tests; git SSH signing integration; no key export; 0600 socket; user LaunchAgent; unexecuted migration runbook; independent review; signed PR
