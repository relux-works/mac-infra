# EPIC-260915-1g0e1c: mac-keyvault-secure-enclave-signer

## Description
mac-keyvault: the workstation as an HSM stand-in (owner 2026-09-15). New Go CLI `mac-keyvault` in this repo (cmd/mac-keyvault, internal/keyvault), same conventions as the other tools (Go 1.25, tuitestkit-style tests, README Tools row, setup.sh build, no root). P-256 private keys are created and kept in the Secure Enclave (kSecAttrTokenIDSecureEnclave) or, when the Enclave is unavailable, in the login Keychain as non-exportable items; they never leave the store \u2014 the CLI only derives publics, signs, verifies. Consumer: kvctl (jc-keyvault, bsim board EPIC-260915-3slg4l) Signer backend `macos-keychain`, so the test PKI root/intermediates never sit in a repo as PEM. Access control: ACL bound to the current user and the calling binary; every prompt macOS shows is documented. Never touch existing Keychain items; tests use throwaway labels under a `works.relux.mac-keyvault.test.` prefix and delete them.

## Scope
(define epic scope)

## Acceptance Criteria
(define acceptance criteria)
