# TASK-260915-273fb3: t6-secret-aes-256-gcm-encrypt-decrypt

## Description
Per key-record-model-v2.md: kind secret, algorithm aes-256-gcm stored as a Keychain secret item with the same SecAccess ACL (use trusted to the binary; export authorization per extraction policy); generation: init --kind secret --algorithm aes-256-gcm (SecRandomCopyBytes 32 bytes) and init --kind secret --generate token:N|password:N[:charset]|bytes:N for opaque secrets; exposure process (material loaded into mac-keyvault memory for one operation, zeroed after, never printed or written unless extraction agent and export-secret is called); aes-256-gcm-encrypt/decrypt over any payload with the shared envelope format; export-secret per extraction policy; registry row; describe reports exposure process.

## Scope
internal/keyvault registry + secret backend, Go crypto/aes+cipher.GCM, cmd/mac-keyvault

## Acceptance Criteria
init --kind secret creates the item; encrypt/decrypt round-trip with test labels; decrypt refused without usages decrypt; tampered tag refused; key material never appears in any output or log (test greps); pub refused for secret kind with a clear message; go test green
