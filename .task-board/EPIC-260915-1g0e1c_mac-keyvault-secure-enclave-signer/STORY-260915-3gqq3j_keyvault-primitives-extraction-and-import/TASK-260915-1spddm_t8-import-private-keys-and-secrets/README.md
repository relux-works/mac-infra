# TASK-260915-1spddm: t8-import-private-keys-and-secrets

## Description
Per key-record-model-v2.md §7 incl. Import detection: import --service S --purpose P --in FILE|--stdin with kind/algorithm/representation detected from the input (PEM headers, then ASN.1 probes PKCS#8 -> SPKI -> X.509 -> PKCS#7 -> PKCS#12); --kind optional and refused when it contradicts detection; unrecognized input refused unless --as-secret; PKCS#12 yields key + certificate records; private keys via SecItemImport with kSecAttrIsExtractable and SecAccess ACL per --extraction; secrets from stdin only, never argv; origin.source imported:<sha256>; prints source_still_on_disk for file inputs and never modifies or deletes the source. Public kinds share the detector with T4; T8 owns the detector module and the private-kind paths.

## Scope
internal/keyvault import bridge (SecItemImport), cmd/mac-keyvault import

## Acceptance Criteria
round-trips with test labels: import PKCS#8 -> describe shows algorithm ec-p256, origin imported:<sha256>, fingerprint equals Go-computed SPKI hash; extraction none import cannot be exported afterwards (executable proof); malformed input refused before any Security call; argv-supplied secret refused; source file unchanged (hash compared); go test green
