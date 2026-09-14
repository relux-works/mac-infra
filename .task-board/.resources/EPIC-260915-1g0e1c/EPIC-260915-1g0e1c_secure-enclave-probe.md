# Secure Enclave availability probe (2026-09-15)

Probe: cgo program calling SecKeyCreateRandomKey (P-256) from a `go build` binary on macOS Darwin 25.5, Apple Silicon. Throwaway label `works.relux.mac-keyvault.test.probe`, deleted after each run; no pre-existing Keychain item touched.

| Case | Signature | Result |
| --- | --- | --- |
| SE, kSecAttrIsPermanent=false | ad-hoc | OK (pub 65 B, DER sig 70-71 B) |
| SE, permanent | ad-hoc | -34018 errSecMissingEntitlement |
| Data Protection keychain, no SE, permanent | ad-hoc | -34018 |
| Login keychain, non-exportable, permanent | ad-hoc | OK; SecItemDelete by tag = 0 |
| SE, permanent | Apple Development + application-identifier + keychain-access-groups entitlements | process SIGKILLed by AMFI (rc 137): restricted entitlements need a provisioning profile, which a bare CLI cannot embed |

Decision recorded for T1: cgo bridge to Security.framework (repo already uses cgo in chromectl/audiodevice); login-keychain non-exportable P-256 keys with an ACL bound to the user and the calling binary are the primary store; `--enclave` refuses explicitly with -34018 and this explanation; Secure Enclave persistence needs a signed .app helper with a registered App ID and provisioning profile and is a separate follow-up, not a silent fallback.