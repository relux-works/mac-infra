# Names

| Term | Meaning in this book |
| --- | --- |
| vault | `mac-keyvault`: non-extractable P-256 key pairs with schema-2 records |
| record | the vault's metadata for one key generation (schema 2) |
| address | `<service>/<purpose>`, plus kind and version |
| generation | the version N of a key; `rotate` creates N+1 and keeps N |
| store | where the private half lives: `keychain` (login keychain) or `enclave` (Secure Enclave via the Swift helper) |
| user presence | Touch ID or login password on every signature of an enclave key created with `--user-presence` |
| signer contract 1 | the JSON-lines protocol of `mac-keyvault signer serve`, bound to one key generation per session |
| agent bridge | `mac-keyvault ssh-agent`: OpenSSH agent protocol over an owner-only socket |
| root helper | `mac-infra-core` installed as a LaunchDaemon for allowlisted privileged actions |
| owner key | the owner-presence enclave key that authorizes selected privileged actions |
| same-UID limit | processes of the same user are not isolated from each other |
