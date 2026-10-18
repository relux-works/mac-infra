# TASK-261019-ftrwzs: enclave-userpresence-acl-and-prompt

## Description
Switch the mac-keyvault-enclave presence ACL from .biometryCurrentSet to .userPresence (policy name user-presence; the old name is refused), and word the presence prompt from what is signed: sha256 prefix by default, action plus package digest prefix for a works.relux.vpn-core.authorize/v1 statement given via --data-file/--stdin. Re-stage mac-keyvault + mac-keyvault-enclave for the agent-run owner key creation.

## Scope
(define task scope)

## Acceptance Criteria
1) Real Secure Enclave: a user-presence key refuses silent signing (-25308) and a no-presence key signs (probe run-01 3/3 + TestEnclaveRealHelper); biometry-current-set create is bad_request. 2) Prompt reason: default names sha256 prefix and key; a recognised statement names action and digest prefix; near-miss statements and --digest fall back to the default; the description applies only to the digest of the hashed data and is cleared after sign. 3) Mutation controls kill each of those checks on an assertion (not compile/panic). 4) Full go test -race green. 5) Codex review ACCEPT; skill mirror updated with tag and README row.
