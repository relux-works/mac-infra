# STORY-261018-w54x4z: keyvault-agent-git-only-signing-audit

## Description
Compensating controls for autonomous agent signing keys (owner 2026-10-18, verbatim via meta-keeper: autonomy without manual approvals, key never in context). (a) ssh-agent --sign-namespace NS: sign only SSHSIG blobs with that namespace; refuse auth challenges and anything else. (b) --audit-log PATH: append-only JSONL per sign request (time, key, fingerprint, namespace, hash prefixes, client pid); never the data; a signature is returned only after its record is written. (c) socket 0600 in owned 0700 dir (exists) with tests. Same-UID access is the accepted residual. No key creation here (B on hold).

## Scope
(define story scope)

## Acceptance Criteria
(define acceptance criteria)
