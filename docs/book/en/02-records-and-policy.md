# 2. Records and policy

An agent that signs with a vault key must never be able to talk the vault into
signing with the wrong key, the wrong generation, or a key the record no longer
allows. Most of that protection comes from the vault's refusals: they are
checked against the record before any call reaches Security.framework, and
they are deliberately narrow. This chapter explains how `mac-keyvault` models
a key and why it refuses the requests it refuses. Commands and options are in
the runbook ([Key Vault Workflow](../../../agents/skills/mac-infra/SKILL.md)).

The limit comes first, because everything below depends on it. These refusals
are policy inside the tool, not an operating-system boundary. Any process
running as the same user can run `mac-keyvault`, so the policy protects a
careful agent from its own mistakes and from malformed input; it does not
protect one same-user process from another. (*source*: the same-UID statement
in the runbook's SSH agent section.)

## A key is a record, not a label

A keychain item alone carries too little to answer the vault's questions:
which purpose a key serves, which generation it is, whether it may still sign.
The vault therefore stores a schema-2 record next to every key and addresses
it by meaning: `<service>/<purpose>`, plus a kind (default `key`) and a version
(default: the newest). The keychain label,
`works.relux.mac-keyvault.<kind>.<service>.<purpose>.v<N>`, is derived from
that address and is never typed by a caller. An agent therefore cannot point
the vault at an arbitrary keychain item by spelling its label: a raw label is
refused before the keychain is consulted. (*source*:
`internal/keyvault/signerclient/record.go` for the `Record` struct and the
label grammar, `internal/keyvault/record.go` `ParseAddress`; *tested*:
`TestParseAddressAndLabel`, `TestRequireOwnLabel`.)

The record names what the key is (kind, algorithm, store), who may take it
out (extraction), what it may be used for (usages), how it is presented (formats), when
it was made and from what (created, origin), its validity window, and an open
`meta` map for operator notes. A key also has generations: `rotate` creates
version N+1 with the record copied and keeps version N, and deleting a
generation needs both `--confirm` and an explicit `--version`. (*source*:
`internal/keyvault/keyvault.go`; *tested*: `TestManagerRotate`,
`TestManagerDeleteGates`.)

The vocabulary is wider than what this revision creates. The kinds
`public-key`, `certificate` and `secret` and the algorithms `ec-p384`,
`rsa-3072` and `ed25519` are named, so a request for them gets a precise
answer instead of a silent substitution. Only kind `key` with algorithm
`ec-p256` is created today. Other kinds are refused as `unsupported_kind`.
`ec-p384` and `rsa-3072` are refused as `unsupported_algorithm`, reserved and
"never mapped to another algorithm". `ed25519` is refused explicitly because
Security.framework's SecKey has no Ed25519 support. (*source*: `ValidateNew` in `internal/keyvault/record.go`,
`validateAlgorithm` in `internal/keyvault/signerclient/invariants.go`;
*tested*: `TestValidateNew`, `TestValidateKind`.)

## One table decides what a record may hold

The vault reads records back from storage it does not fully control: an item
can be edited outside the tool, or a record written by an older revision.
Early review rounds found forged stored fields one at a time: an issuer on a
key, a trailing document, a `not_before` on a key. The response was to close
the class instead of the instances. One invariant table holds exactly one row
per record field and states what that field may contain for each kind. `init`,
`rotate` and `meta set|unset` run the whole table before any Security call;
`describe` and `list` run it and report a failing row as a finding,
`record_invalid:<code>`, instead of refusing to show the item. (*source*: the
header comment and `recordInvariants` in
`internal/keyvault/signerclient/invariants.go`; *tested*:
`TestRecordInvariantsCoverEveryField`, which compares the table with the
`Record` fields, and `TestForgedStoredRecordRefusedEverywhere`, which forges
fields in stored records.)

Some refusals follow from the table directly. A Secure Enclave key can never be
made extractable. An extraction policy other than `none` is accepted only for
kinds that carry one, `key` and `secret`. (*source*: `validateExtraction` in
`invariants.go`.)

A stored record that carries a JSON member the schema does not define is a
different case: it is unreadable, not merely invalid. `rotate` and `meta set`
or `unset` refuse it with `metadata_unknown`, call nothing that would create or
update a keychain item, and leave the stored tag byte-identical; `describe`
still lists the item with the finding `record_unreadable`. Only `meta` is an
open map. A field that must change behaviour is added to the schema rather
than smuggled into the record and silently dropped. (*tested*:
`TestRunUnknownRecordFieldIsUnreadableEverywhere` in
`cmd/mac-keyvault/main_test.go`, including the positive control that the same
member name inside `meta` stays readable; `TestDecodeRecordRefusesNestedDuplicateMembers`.)

## Refusing early, and saying why

Every invalid name, raw label, reserved name inside `meta` or unknown
vocabulary value is refused with exit code 3 before Security.framework is
called; the test asserts that such a request never even lists the store. A
duplicate `(kind, service, purpose)` needs one lookup to be detected; it is
then refused with exit code 3 and nothing is created. A refusal is not a
failure to retry: the input has to change. Operational failures from the keychain
(`not_found`, `missing_entitlement`, `security`) use exit code 1, so an agent
can tell "fix your request" from "the system said no". Every outcome,
including usage errors, is one JSON envelope on stdout with `error.code` and
`error.hint`. (*source*: `cmd/mac-keyvault/main.go`; the runbook's exit-code
table; *tested*: `TestManagerInitValidatesThenGatesDuplicates`, and
`TestManagerInitDuplicateRefusalIsAtomic` for the duplicate case.)

Signing has its own gates, checked before any keychain call. `sign` accepts
a SHA-256 digest or hashes the input itself and reports that it did. It
refuses a digest of the wrong length (`invalid_digest`), a record without the
usage `sign` (`usage_refused`), a record whose `validity.not_after` has passed
(`expired`), an unreadable or forged record (`metadata_unknown`), and an
operation with no registered primitive (`unsupported_primitive`). The
signature it returns is strict DER with a low S value. When the keychain
produced a high S, the vault folds it and says so with `normalized: true`.
(*source*: `internal/keyvault/keyvault.go`, `signer.go`, `ecdsa.go`;
*tested*: `TestManagerSignGates`, and `TestOperationsRegistry` for the
operations a record allows.)

`verify` is stricter about input than about keys. It decides on the
signature bytes first: malformed DER, a wrong raw length, or a high S value
is refused with exit 3 before the vault or a public-key file is read. A
well-formed signature that does not match the data is exit 1, `verified:
false`. `--allow-high-s` exists for signers known not to normalise, and an
agent never passes it by default. (*source*: `internal/keyvault/ecdsa.go`;
*tested*: `TestParseSignatureStrictness`.)

## What the record does not do

The extraction policy defaults to `none`. The commands that would take a
private key out, `export-private` and `--human-authorized`, are not implemented
in this revision. A key with `extraction: none` therefore has no export path at
all, not one that merely needs permission. The record cannot express "only
this agent may sign". Usage and validity restrict *what* a key does, never
*who* asks, because the caller's identity is not something the vault can
establish under the same-UID limit. (*source*: the runbook's extraction
paragraph; `cmd/mac-keyvault/main.go` has no such command.)

The practical consequence for anyone adding a key: choose the address and
usages deliberately at `init`, because they are the policy. Rotate instead of
editing; treat a `record_invalid` or `record_unreadable` finding as "delete
and recreate", never as a record to copy. Put probes under `--service test`
and delete them afterwards.

## Sources

| Paragraph | Evidence at `2351093` |
| --- | --- |
| Opening, limit | runbook `agents/skills/mac-infra/SKILL.md` (Key Vault Workflow; SSH agent bridge, same-UID statement) |
| A key is a record | `internal/keyvault/signerclient/record.go` (Record, label grammar); `internal/keyvault/record.go` (ParseAddress); tests TestParseAddressAndLabel, TestRequireOwnLabel |
| Record contents, generations | `internal/keyvault/signerclient/record.go`; `internal/keyvault/keyvault.go`; TestManagerRotate, TestManagerDeleteGates |
| Vocabulary vs creation scope | `internal/keyvault/record.go` ValidateNew; `invariants.go` validateAlgorithm; TestValidateNew, TestValidateKind |
| Invariant table | `internal/keyvault/signerclient/invariants.go` (header, recordInvariants); TestRecordInvariantsCoverEveryField, TestForgedStoredRecordRefusedEverywhere |
| Extraction refusals | `invariants.go` validateExtraction |
| Unreadable records | `cmd/mac-keyvault/main_test.go` TestRunUnknownRecordFieldIsUnreadableEverywhere; TestDecodeRecordRefusesNestedDuplicateMembers |
| Early refusals, exit codes | `cmd/mac-keyvault/main.go`; TestManagerInitValidatesThenGatesDuplicates (invalid input: zero store creates and lists; duplicate: zero creates), TestManagerInitDuplicateRefusalIsAtomic |
| Sign gates | `keyvault.go`, `signer.go`, `ecdsa.go`; TestManagerSignGates, TestOperationsRegistry |
| Verify strictness | `ecdsa.go`; TestParseSignatureStrictness |
| Not implemented | runbook extraction paragraph; absence in `cmd/mac-keyvault/main.go` |

Status: *source* and *tested* at the pin, as cited. Nothing here is a claim
about an installed binary.
