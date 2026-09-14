# TASK-260915-tkat1p: t4-public-key-and-certificate-import-export

## Description
Per STORY resource key-record-model-v2.md: kind public-key (import peer SPKI DER/PEM as a Keychain public SecKey item under the same label space, issuer {kind: imported, from, user, host}) and kind certificate (import X.509 DER/PEM as SecCertificate, validity/issuer copied from the cert, linked to a key by SHA-256(SPKI)); generation from a vault key: cert self-sign <service>/<purpose> --subject ... --days N and csr <service>/<purpose> --subject ... (signed through the vault, private key never leaves); export with representation conversion: export --format x509-der|x509-pem|pkcs7-chain (chain assembled from vault certificates up to the root when present) and a Keychain-free convert DER<->PEM<->PKCS7 for files; pkcs12 export only under T7 extraction rules; verify (T2) accepts these kinds; registry rows for both.

## Scope
internal/keyvault registry + backend, cmd/mac-keyvault import/export

## Acceptance Criteria
import/export round-trips against the login keychain with test labels; malformed DER/PEM refused before any Security call; import under a foreign prefix impossible; verify with an imported public-key/certificate passes and a tampered signature fails; describe shows the public-only operations set; go test green
