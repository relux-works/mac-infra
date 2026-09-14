# TASK-260915-1ck31n: t7-exportable-keys-and-human-authorized-export

## Description
Per key-record-model-v2.md: init --extraction none|human|agent. none (default): kSecAttrIsExtractable=false. human: extractable with a split SecAccess ACL (use trusted to the calling binary; export authorizations kSecACLAuthorizationExportClear/ExportWrapped with no trusted applications and prompt-selector requiring the passphrase every time); export-private <service>/<purpose> --human-authorized --out FILE --format pkcs8-der|pkcs8-pem|pkcs12 via SecItemExport so macOS prompts. agent: kind secret only, export-secret without prompt; init --kind key --extraction agent refused. Refusals: export without --human-authorized where required (exit 3), extraction none, enclave keys. describe lists export-* only when extraction allows; SKILL.md documents that agents never pass --human-authorized.

## Scope
internal/keyvault ACL construction + export bridge, cmd/mac-keyvault export-private, docs

## Acceptance Criteria
exportable key: sign without prompt, export prompts (manual smoke documented, not automated); non-exportable key: export refused with clear message before any Security call; --human-authorized absent: refused; exported PKCS#8 parses with Go x509.ParsePKCS8PrivateKey and matches the vault fingerprint; tests use test labels and delete them; go test green
