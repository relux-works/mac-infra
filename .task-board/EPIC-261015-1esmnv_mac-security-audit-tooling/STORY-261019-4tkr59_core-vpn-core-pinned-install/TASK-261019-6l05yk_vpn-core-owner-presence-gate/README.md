# TASK-261019-6l05yk: vpn-core-owner-presence-gate

## Description
Owner decision F1 (Alexis 2026-10-19 ~13:30Z via meta): gate vpn-core install/rollback on an owner Secure Enclave signature before PR #20 lands. Helper-issued authz statement (nonce 32B, 120s TTL, single-use, bound to uid/action/target/framed digest), ECDSA P-256 DER low-S over sha256(statement) by mac-keyvault sign --data-file, verified against a pinned SPKI written only by the sudo helper install (root:wheel 0444). No pin = refuse.

## Scope
(define task scope)

## Acceptance Criteria
1) vpn-core authorize issues the exact v1 statement; install/rollback require --authorization/--signature and refuse before any write when: pin missing or unsafe, signature missing/invalid/high-S, wrong key, statement not issued or altered, nonce unknown/expired/reused, statement for another digest/action/target/uid, replay of an older statement. 2) mac-infra-core install --owner-key/--expect-owner-key-sha256 pins the SPKI atomically as root:wheel 0444; a wrong sha or a non-P-256 key refuses before writing. 3) Every refusal keeps install/plist bytes and makes no launchctl call; audit records the refusal. 4) Mutation controls: removing each gate check turns a named test red. 5) Codex review ACCEPT and sysadmin security review of the delta.
