# 3. Where keys live

A signing agent needs a signature without receiving the private key.
Choosing a store also chooses how the operating system authorizes its use.
Which protections come from the login Keychain, and which require the Secure
Enclave?
This chapter follows creation, storage and signing in those two stores.
The record supplies the store choice; `RoutedBackend` carries it to the
backend.
(*source*: `internal/keyvault/enclave_store.go`, `RoutedBackend.Create`
and `RoutedBackend.SignIn`.)
Commands belong in the [Key Vault Workflow](../../../agents/skills/mac-infra/SKILL.md#key-vault-workflow).

## Keychain: trust the binary, retain the private half

The login-Keychain backend asks Security.framework to generate a permanent
P-256 key.
`MacKeyVaultCreate` sets `kSecAttrIsExtractable=false` at the top level
of the creation dictionary.
The bridge returns the public point.
For signing, `MacKeyVaultSign` passes a digest to `SecKeyCreateSignature`
and returns the signature.
The private half stays inside Security.framework along these paths.
This is a framework boundary, not hardware confinement.
(*source*: `internal/keyvault/security_darwin.c`, `MacKeyVaultCreate`
and `MacKeyVaultSign`.)

The repository checks two private-key export paths from the trusted binary.
`TestSecurityStorePrivateKeyIsNotExtractable` requires both
`SecKeyCopyExternalRepresentation` and wrapped-PKCS8 `SecItemExport`
to return `errSecDataNotAvailable` (-25316), with zero leaked bytes.
It also checks that the public half remains readable.
That is the test's scope.
It does not prove resistance to every way of compromising macOS.
(*tested*: `internal/keyvault/security_darwin_test.go`,
`TestSecurityStorePrivateKeyIsNotExtractable`.)

The item's private-key ACL trusts the creating executable.
`MacKeyVaultCreateAccess` builds a one-application list using
`SecTrustedApplicationCreateFromPath(NULL)`.
`TestSecurityStoreACLTrustsOnlyCallingBinary` reads the ACL back and
requires every entry guarding private-key authorization to trust exactly
the running executable.
It does not require every ACL entry to be closed; public-operation entries
are outside that assertion.
(*source*: `internal/keyvault/security_darwin.c`,
`MacKeyVaultCreateAccess`; *tested*:
`internal/keyvault/security_darwin_test.go`,
`TestSecurityStoreACLTrustsOnlyCallingBinary`.)

A rebuilt executable must be re-trusted for affected Keychain keys.
The runbook describes the next private-key use prompting, with “Always
Allow” retaining trust and “Allow” permitting one use.
This is documented operating-system behavior, not a rebuild test.
The build guard describes the wait as applying to each key; an exact prompt
count is *unknown* here.
The owner decision is to freeze routine rebuilds while unattended users
depend on the binary.
`setup.sh` keeps an existing executable unless `--rebuild-keyvault`
is requested.
Its guard refuses an active consumer or an inconclusive inspection.
That preserves unattended use at the cost of postponing updates until a
planned owner sitting.
(*source*: `agents/skills/mac-infra/SKILL.md`, “ACL prompts”;
`scripts/setup.sh`, `KEYVAULT_DECISION`;
`scripts/keyvault-build-guard.sh`, rebuild gates.)

## Enclave: keep a device-bound blob

An Enclave key needs a stored blob even though its usable private half stays
in hardware.
The Swift helper `mac-keyvault-enclave` creates a
`SecureEnclave.P256.Signing.PrivateKey` and returns its
`dataRepresentation` with the public point.
Go stores that representation.
Apple describes it as an encrypted block restorable only by the same Secure
Enclave in [Storing CryptoKit Keys](https://developer.apple.com/documentation/cryptokit/storing-cryptokit-keys-in-the-keychain).
The private half never leaving the Enclave is a relied-on Apple property,
not a repository proof; see [Protecting keys](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave).
Device binding therefore prevents using the blob as a portable private-key
backup.
(*source*: `cmd/mac-keyvault-enclave/main.swift`, `create`, `loadKey`.)

The blob file also carries the record and public point.
Creation requests mode `0600` for the file and `0700` for the directory.
`TestEnclaveInitStoresPresenceKeyWithoutKeychain` checks those resulting
modes with a fake helper.
Readers check the opened descriptors for ownership and reject group or
other permission bits.
They refuse symlinked store directories and symlinked or multiply linked
key files.
These checks restrict filesystem access; they do not isolate same-user
processes.
(*source*: `internal/keyvault/enclave_store.go`, `enclaveFile`,
`ensureDir`; `internal/keyvault/enclave_perm_unix.go`,
`writeEnclaveFileAt`, `openEnclaveDir`, `readEnclaveFileAt`;
*tested*: `internal/keyvault/enclave_store_test.go`,
`TestEnclaveInitStoresPresenceKeyWithoutKeychain`.)

## Presence: authorize a use, inspect the reason

Choose `--enclave --user-presence` for signatures that require an attending
owner.
The helper requests `.privateKeyUsage` plus `.userPresence`.
It creates a fresh authentication context for a requested signature and
sets no reuse duration.
The intended macOS behavior is Touch ID or the login password for every
signature, making this unsuitable for unattended signing.
Apple's [userPresence definition](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence)
allows biometric enrollment changes without invalidating access.
These are operating-system semantics the helper relies on.
(*source*: `cmd/mac-keyvault-enclave/main.swift`, `accessControl`, `sign`;
`agents/skills/mac-infra/SKILL.md`, Enclave presence policy.)

The helper checks that a key really requires presence instead of trusting
the record's flag alone.
`presenceEnforced` attempts a signature over a random probe digest with
interaction forbidden.
A successful probe identifies a key without presence.
Creation reports that verdict; Go refuses to store a key whose verdict
differs from the request.
Signing a record requiring presence checks again.
`TestEnclaveRealHelper` asserts refusal at -25308 for noninteractive
presence signing and rejection of a silent key swapped under a presence
record.
It does not exercise interactive approval or fingerprint changes.
(*source*: `cmd/mac-keyvault-enclave/main.swift`, `presenceEnforced`,
`create`, `sign`; `internal/keyvault/enclave_store.go`,
`EnclaveStore.Create`; *tested*:
`internal/keyvault/enclave_helper_darwin_test.go`, `TestEnclaveRealHelper`.)

The prompt reason normally names the first eight hexadecimal characters
of the SHA-256 digest and the key's service, purpose and generation.
When the CLI hashes a recognized vpn-core authorization statement, it
substitutes the action and package-digest prefix.
`TestSignPromptNamesTheSignedData` checks these strings delivered to a
fake helper, not a rendered system dialog.
The Swift helper removes control characters and limits the reason to
200 Unicode scalars before setting `localizedReason`.
A caller can supply its own reason, so the text helps detect mistakes but
does not authenticate the caller's intent.
(*source*: `internal/keyvault/enclave_store.go`, `enclaveReason`;
`cmd/mac-keyvault/prompt.go`, `describeData`;
`cmd/mac-keyvault-enclave/main.swift`, `sign`; *tested*:
`cmd/mac-keyvault/prompt_test.go`, `TestSignPromptNamesTheSignedData`.)

Keychain `--user-presence` takes a different path.
The C bridge requests access control from Security.framework.
On the unprovisioned binary covered by
`TestSecurityStoreEnclaveAndUserPresenceReturnMissingEntitlement`, the
framework returns -34018 and leaves no key.
`Translate` exposes that status as `missing_entitlement`.
This refusal comes from the operating system, not a CLI prohibition of
all possible provisioned builds.
(*source*: `internal/keyvault/security_darwin.c`, `MacKeyVaultCreate`;
`internal/keyvault/keyvault.go`, `Translate`; *tested*:
`internal/keyvault/security_darwin_test.go`,
`TestSecurityStoreEnclaveAndUserPresenceReturnMissingEntitlement`.)

## A missing store is a refusal

An Enclave failure does not authorize creating or signing with a Keychain
key instead.
Creation routes by the request; managed signing routes by the authorized
record.
`TestEnclaveInitRefusesWrongPresenceAndNeverFallsBack` injects an
unavailable-Enclave error and requires no stored file and no Keychain
creation.
That proves the injected failure case, not hardware availability.
(*source*: `internal/keyvault/enclave_store.go`,
`RoutedBackend.Create`, `RoutedBackend.SignIn`; *tested*:
`internal/keyvault/enclave_store_test.go`,
`TestEnclaveInitRefusesWrongPresenceAndNeverFallsBack`.)

Without a resolvable helper, valid existing Enclave files remain listable,
describable and deletable.
Signing is refused as `unsupported_primitive` before a helper call.
Creation also fails, but its missing-helper error does not pass through that
signing gate.
`TestEnclaveStoreWithoutHelper` asserts listing, deletion, failed creation
and the signing refusal.
The production helper is resolved beside the running executable, not through
`PATH`.
Resolution does not prove that this Mac has a usable Secure Enclave.
Availability on a particular Mac remains *unknown* until established
separately.
(*source*: `internal/keyvault/enclave_store.go`, `DefaultEnclaveStore`,
`EnclaveStore.Serves`; `internal/keyvault/keyvault.go`,
`Manager.authorize`; *tested*: `internal/keyvault/enclave_store_test.go`,
`TestEnclaveStoreWithoutHelper`.)

## What this does not protect against

A same-user process can invoke the vault or call the Enclave helper with a
copied blob.
The CLI authenticates no individual agent, and helper ownership checks
permit the current user.
This is an architectural inference from `cmd/mac-keyvault/main.go`,
`newBackend`, and `internal/keyvault/enclave_perm_unix.go`,
`requireOwnedFile` (*source*).
Protection against a root adversary is outside this book's stated scope.
Keep the store choice and presence policy explicit, and report denied or
unavailable prompts instead of retrying around them.
That operational rule is stated in the runbook's Enclave and ACL guidance
(*source*: `agents/skills/mac-infra/SKILL.md`; root-adversary scope:
`docs/book/editorial/outline.md`, chapter 1).

**Status.** Source was checked at
`13a5c3ec7fb289afe945a90f6b4b2557c41fd9d9`, the job's pin.
*Tested* marks identify assertions read, not tests run for this chapter.
No installed-state claim is made.
Hardware confinement and authentication semantics remain relied-on Apple
behavior.

## Sources

| Paragraph | Path and function or symbol | Test asserting the stated case |
| --- | --- | --- |
| Opening: store choice | `internal/keyvault/enclave_store.go`: `RoutedBackend.Create`, `SignIn` | None |
| Keychain generation and signing | `internal/keyvault/security_darwin.c`: `MacKeyVaultCreate`, `MacKeyVaultSign` | None |
| Two export paths | `internal/keyvault/security_darwin.c`: `MacKeyVaultProbeExport`; `internal/keyvault/security_darwin_test.go` | `TestSecurityStorePrivateKeyIsNotExtractable` |
| Private-key ACL | `internal/keyvault/security_darwin.c`: `MacKeyVaultCreateAccess`; `internal/keyvault/security_darwin_test.go`: ACL assertions | `TestSecurityStoreACLTrustsOnlyCallingBinary` |
| Rebuild and freeze | `scripts/setup.sh`: `KEYVAULT_DECISION`; `scripts/keyvault-build-guard.sh`: rebuild gates; `agents/skills/mac-infra/SKILL.md`: ACL prompts | None; prompt count unknown |
| Device-bound representation | `cmd/mac-keyvault-enclave/main.swift`: `create`, `loadKey`; Apple links above | None; hardware properties relied on |
| Files and permissions | `internal/keyvault/enclave_store.go`: `enclaveFile`, `ensureDir`; `internal/keyvault/enclave_perm_unix.go`: `openEnclaveDir`, `readEnclaveFileAt`, `writeEnclaveFileAt`; `internal/keyvault/enclave_store_test.go` | `TestEnclaveInitStoresPresenceKeyWithoutKeychain` (creation modes) |
| Presence choice | `cmd/mac-keyvault-enclave/main.swift`: `accessControl`, `sign`; runbook and Apple link above | None; authentication semantics relied on |
| Presence enforcement probe | `cmd/mac-keyvault-enclave/main.swift`: `presenceEnforced`; `internal/keyvault/enclave_store.go`: `Create`; `internal/keyvault/enclave_helper_darwin_test.go` | `TestEnclaveRealHelper` (noninteractive cases) |
| Prompt reason | `internal/keyvault/enclave_store.go`: `enclaveReason`; `cmd/mac-keyvault/prompt.go`: `describeData`; `cmd/mac-keyvault-enclave/main.swift`: `sign`; `cmd/mac-keyvault/prompt_test.go` | `TestSignPromptNamesTheSignedData` |
| Keychain presence refusal | `internal/keyvault/security_darwin.c`: `MacKeyVaultCreate`; `internal/keyvault/keyvault.go`: `Translate`; `internal/keyvault/security_darwin_test.go` | `TestSecurityStoreEnclaveAndUserPresenceReturnMissingEntitlement` |
| No fallback | `internal/keyvault/enclave_store.go`: `RoutedBackend.Create`, `SignIn`; `internal/keyvault/enclave_store_test.go` | `TestEnclaveInitRefusesWrongPresenceAndNeverFallsBack` |
| Missing helper and availability | `internal/keyvault/enclave_store.go`: `DefaultEnclaveStore`, `Serves`; `internal/keyvault/keyvault.go`: `authorize`; `internal/keyvault/enclave_store_test.go` | `TestEnclaveStoreWithoutHelper` |
| Same-user limit and response to prompts | `cmd/mac-keyvault/main.go`: `newBackend`; `internal/keyvault/enclave_perm_unix.go`: `requireOwnedFile`; runbook prompt guidance; `docs/book/editorial/outline.md`, chapter 1 | None; architectural inference |
| Status | Job pin; cited test assertions and Apple behavior | No execution claim |
