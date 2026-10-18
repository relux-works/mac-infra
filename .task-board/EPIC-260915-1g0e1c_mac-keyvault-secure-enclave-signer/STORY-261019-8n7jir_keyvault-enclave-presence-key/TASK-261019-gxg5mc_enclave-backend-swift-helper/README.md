# TASK-261019-gxg5mc: enclave-backend-swift-helper

## Description
Add a Secure Enclave backend to mac-keyvault: a small Swift helper (CryptoKit SecureEnclave.P256.Signing.PrivateKey + SecAccessControl) for create/public/sign, a tool-owned 0600 blob store, init --enclave --user-presence on it, pub ssh, SSHSIG sign, ssh-agent exposure. Installed bin/mac-keyvault is FROZEN: build and stage under .temp only; the swap and the owner key creation happen at the owner morning sitting.

## Scope
(define task scope)

## Acceptance Criteria
1) init --enclave [--user-presence] creates an SE key with no keychain entitlement and no keychain item; --user-presence means Touch ID only (biometryCurrentSet), stated in help. 2) No software fallback ever: SE unavailable or create failure refuses and creates nothing. 3) pub --format ssh reads the stored public key without presence. 4) sign and the ssh-agent bridge produce SSHSIG ECDSA verified by ssh-keygen -Y verify; every signature uses a fresh LAContext with no reuse. 5) Negative tests: signing without presence (interactionNotAllowed) is refused with a stable code; tampered blob, blob/pub mismatch, foreign label and symlinked or group/world-accessible blob files are refused; no fallback to keychain. 6) Existing keychain keys, the relux-release agent and all current tests unchanged and green. 7) Codex independent review ACCEPT; staged binary sha reported for the morning line.
