# TASK-260915-57shde: t5-ecies-payload-encrypt-decrypt

## Description
Per key-record-model-v2.md: ecies-p256-encrypt (any public primitive) and ecies-p256-decrypt (key pair, usages decrypt) with SecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM, exposure never; payload via --data-file/--stdin/--data-hex; envelope {alg, nonce, aad, ciphertext, tag} JSON or --der; registry rows; interop test decrypts in Go what the tool encrypted and vice versa where Go supports it.

## Scope
internal/keyvault registry + cgo bridge, cmd/mac-keyvault encrypt/decrypt

## Acceptance Criteria
round-trip against login keychain with test labels; decrypt refused without usages decrypt (exit 3); tampered envelope refused; wrong key refused; envelope never omits parameters; go test green
