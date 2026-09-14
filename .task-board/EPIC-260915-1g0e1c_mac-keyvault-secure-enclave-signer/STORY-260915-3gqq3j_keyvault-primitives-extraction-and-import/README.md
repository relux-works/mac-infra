# STORY-260915-3gqq3j: keyvault-primitives-extraction-and-import

## Description
Second slice of mac-keyvault on top of the landed first slice (key store + record model v2, sign/verify, signer contract): public-key/certificate kinds with import/export/representation conversion and self-sign/csr (T4), ECIES payload encrypt/decrypt (T5), secret kind aes-256-gcm + opaque generators (T6), extraction policy none/human/agent with human-authorized export (T7), import of private keys and secrets with format detection (T8). Normative source: STORY-260915-3r0ys5 resource key-record-model-v2.md (copy or link it here before spawning).

## Scope
cmd/mac-keyvault, internal/keyvault (registry rows, backends, import detector), signerclient additions if the wire grows, docs

## Acceptance Criteria
each task accepted through review with its named negative tests; registry rows added without special cases in commands; no existing Keychain item touched; go vet/build/test -count=1 ./... green; Story lands as one signed squash on main
