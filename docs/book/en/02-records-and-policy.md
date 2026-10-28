# 2. Records and policy

An agent that signs with a vault key must not be able to talk the vault into
signing with the wrong key, the wrong generation, or a key whose record no
longer allows it. Most of that protection comes from the vault's refusals,
which are deliberately narrow. Some run on the caller's input alone, before
the vault touches the keychain at all. Others need the stored record first:
they run after a metadata read, and their job is to stop key creation,
record writes and private-key signing. This chapter explains how
`mac-keyvault` models a key and which refusal happens where. Commands and
options are in the runbook ([Key Vault Workflow](../../../agents/skills/mac-infra/SKILL.md)).

One limit frames everything below. These refusals are policy inside the
tool, not an operating-system boundary between callers. The vault does not
authenticate which process invokes it, so any process running as the same
user can run `mac-keyvault` with the same rights. This is an architecture
limit of the tool, inferred from the absence of caller authentication; the
runbook states the same limit for the SSH agent socket. The policy protects a
careful agent from its own mistakes and from malformed input. It does not
separate one same-user process from another.

## A key is a record, not a label

A keychain item alone cannot answer the vault's questions: which purpose a
key serves, which generation it is, whether it may still sign. The vault
therefore keeps a schema-2 record with every key and addresses it by meaning:
`<service>/<purpose>`, plus a kind (default `key`) and a version (default:
the newest). The keychain label,
`works.relux.mac-keyvault.<kind>.<service>.<purpose>.v<N>`, is derived from
that address and never typed by a caller. A raw label passed where an address
is expected is refused at the CLI entry, before any store call, so an agent
cannot aim the vault at an arbitrary keychain item by spelling its label.
(*source*: `internal/keyvault/signerclient/record.go` for the `Record` struct
and label grammar, `internal/keyvault/record.go` `ParseAddress`; *tested*:
`TestRunForeignLabelRefusedAtEntry` for the call order,
`TestParseAddressAndLabel` and `TestRequireOwnLabel` for the grammar.)

The record states what the key is (kind, algorithm, store), whether and by
whom it may be extracted, what it may be used for (usages), how outputs are
presented (formats), when and from what it was made (created, origin), its
validity window, and an open `meta` map for operator notes. Keys have
generations. `rotate` creates version N+1 from a copy of the record and keeps
version N. The copy includes the validity window, so rotation does not repair
an expired `not_after`. `delete` requires `--confirm`, because it destroys the
private key irreversibly. Without `--version`, delete targets the newest
generation; naming the version explicitly is the safer habit, but the tool
does not enforce it. (*source*: `internal/keyvault/keyvault.go`
`Manager.Rotate`, `Manager.Delete` and its refusal message; *tested*:
`TestManagerRotate`, and `TestManagerDeleteGates`, which includes a confirmed
delete of the newest generation without a version.)

The vocabulary is wider than what this revision creates. The kinds
`public-key`, `certificate` and `secret` and the algorithms `ec-p384`,
`rsa-3072` and `ed25519` are named, so a request for them gets a precise
answer instead of a silent substitution. Only kind `key` with algorithm
`ec-p256` is created today. Other kinds are refused as `unsupported_kind`.
`ec-p384` and `rsa-3072` are refused as reserved and "never mapped to another
algorithm". `ed25519` is refused explicitly because Security.framework's
SecKey has no Ed25519 support. (*source*: `ValidateNew` in
`internal/keyvault/record.go`, `validateAlgorithm` in
`internal/keyvault/signerclient/invariants.go`; *tested*: `TestValidateNew`,
`TestValidateKind`.)

## One table decides what a record may hold

The vault reads records back from storage it does not fully control: an item
can be edited outside the tool, or written by an older revision. The header
comment of the invariant code records that review rounds rev1–rev5 found
forged stored fields one at a time, for example an `issuer` on a key or a
`not_before` on a key. The design answer was to close the class rather than
the instances. One invariant table has a row for every record field except
`user_presence`, and each row states what the field may contain for each kind.
`user_presence` is a request flag that the storage backend answers: it is
never true on a binary that is not provisioned for it, so it carries no row,
and the coverage test skips it by name. (*source*: header comment and
`recordInvariants` in `internal/keyvault/signerclient/invariants.go`;
*tested*: `TestRecordInvariantsCoverEveryField`, which compares the rows with
the `Record` fields and names the exception.)

Where the table runs matters. For a new key, `init` validates the caller's
input against the table before anything reaches the store. For an existing
key, `rotate`, `meta set|unset` and `sign` first read the stored metadata,
because that record is the thing being judged, and then run the table. A
failing row stops the operation before a key is created, a tag is
rewritten, or the private key signs. It does not prevent the metadata read
itself. `describe` and `list` run the same table and report a failing row as
a finding, `record_invalid:<code>`, instead of hiding the item. (*source*:
`Manager.resolve`, `Manager.Rotate`, `updateMeta` and the sign path in
`internal/keyvault/keyvault.go`; *tested*:
`TestForgedStoredRecordRefusedEverywhere`, which asserts no creates, no tag
updates, no signatures and unchanged tags for forged records.)

Some refusals follow from the table directly. A Secure Enclave key can never
be made extractable, and an extraction policy other than `none` is accepted
only for the kinds that carry one, `key` and `secret`. (*source*:
`validateExtraction` in `invariants.go`.)

A stored record carrying a JSON member the schema does not define is a
different case: it is unreadable, not merely invalid. `rotate` and
`meta set|unset` refuse it with `metadata_unknown`, make no create or tag
update call, and leave the stored tag byte-identical. `describe` still lists
the item with the finding `record_unreadable`. Only `meta` is an open map: a
field that must change behaviour is added to the schema rather than smuggled
into the record. (*tested*: `TestRunUnknownRecordFieldIsUnreadableEverywhere`
in `cmd/mac-keyvault/main_test.go`, including the positive control that the
same member name inside `meta` stays readable;
`TestDecodeRecordRefusesNestedDuplicateMembers`.)

## Refusing early, and saying why

The vault separates three classes of "no", each with its own exit code.
- **Usage errors** (exit 2): the command line could not be parsed, or a file
  it names could not be read.
- **Policy refusals** (exit 3): an invalid name, a raw label, a reserved name
  inside `meta`, an unknown vocabulary value, or a duplicate
  `(kind, service, purpose)`. Invalid input never reaches the store; the test
  asserts zero store creates and zero lists for it. A duplicate needs one
  lookup to be detected, and is then refused without creating anything.
- **Operational failures** (exit 1): `not_found`, `missing_entitlement`,
  `security`.

A refusal is not something to retry: the request has to change. With
`--json`, every outcome is one envelope on stdout: success carries `ok`,
`command` and `result`; a failure carries `error` with `code`, `message` and
`hint`. Without `--json`, the command prints its output and reports errors
and hints on stderr. (*source*: `cmd/mac-keyvault/main.go` output handling;
*tested*: `TestRunJSONEnvelopeAndExitCodes`,
`TestRunUsageErrorsAreJSONEnvelopesAndDoNotReachStore`,
`TestManagerInitValidatesThenGatesDuplicates`,
`TestManagerInitDuplicateRefusalIsAtomic`.)

Signing has its own gates. `sign` accepts a SHA-256 digest, or hashes the
data itself and reports that it did. A digest of the wrong length
(`invalid_digest`) is refused before any store call. After the stored record
is read, `sign` refuses a record without the usage `sign` (`usage_refused`),
a record whose `validity.not_after` has passed (`expired`), a forged or
legacy record (`metadata_unknown`), and an operation with no registered
primitive (`unsupported_primitive`), in each case before the private key
signs. The output is either strict DER (`ecdsa-der-low-s`) or 64-byte raw
`r||s` (`ecdsa-raw`). It is chosen by `--raw` or `--format`, and otherwise
by the record's signature format. Both representations carry a low S value;
when the keychain produced a high S, the vault folds it and reports
`normalized: true`. (*source*: the sign path in `internal/keyvault/keyvault.go`,
`signer.go`, `ecdsa.go`, `runSign` in `cmd/mac-keyvault/main.go`; *tested*:
`TestManagerSignGates`, which asserts zero store calls for a mis-sized digest
and zero signatures for the usage, expiry and store gates;
`TestForgedStoredRecordRefusedEverywhere` for forged records;
`TestRunSignFormatsAndInterop` for both formats and high-S normalization.)

`verify` checks its inputs and the signature syntax before it loads a public
key or opens the vault. It resolves the digest first, then reads the
signature bytes and parses them strictly. A missing, contradictory,
undecodable or unreadable argument is a usage error (exit 2). A mis-sized digest
(`invalid_digest`) or a malformed signature (`invalid_signature`) is a
policy refusal (exit 3). None of these reaches the store. By default a
high-S signature is refused at the same point, with `high_s_refused`, before
the `--spki` file is read or the vault is listed, unless the caller passes
`--allow-high-s` for a signer known not to normalise; an agent never passes
it by default. An `--spki` file that does not hold a P-256 public key is
refused with `invalid_public_key` once it has been read, still without a
store call. A well-formed signature that does not match the data is exit 1
with `verified: false`.
(*source*: `runVerify` in `cmd/mac-keyvault/main.go`, `ecdsa.go`; *tested*:
`TestRunVerifyHighSRefusedBeforeStore` with a low-S control that does reach
the store; `TestRunVerifyVerdicts` for the mismatch verdict and the explicit
override; `TestRunSignVerifyRefuseBadInputBeforeStore` for malformed input.
`TestParseSignatureStrictness` covers the parser only, and deliberately
accepts a high-S signature as parseable.)

## What the record does not do

The extraction policy defaults to `none`. At this revision the CLI and the
signer contract offer no operation that exports a private key:
`export-private` and `--human-authorized` are not implemented, and the
signer contract consists of `describe`, `pub`, `sign` and `verify` only. That
is a statement about these interfaces. Whether the key material can leave its
store by other means is a property of the store itself, the Keychain or the
Secure Enclave, and is treated with its own evidence in the next chapter.
The record cannot express "only this agent may sign". Usages and validity
restrict *what* a key does, never *who* asks, because the vault does not
authenticate its caller (the same-UID limit above). (*source*: the runbook's
extraction paragraph and signer contract; `cmd/mac-keyvault/main.go` command
set.)

The practical consequence for anyone adding a key: the address and usages
chosen at `init` are the policy, so choose them deliberately. Use `rotate` to
move to a new generation of a valid key; it keeps the old one and copies the
record, validity included. A `record_invalid` or `record_unreadable` finding
means the stored policy must not be reproduced. Recovery is an operator
decision, not an automatic step. Keep the current key until its dependent
uses (agent sockets, signing configurations, published public keys) are
accounted for, and only then create a replacement, under a fresh address
where that keeps identities clear. Deleting a generation is irreversible.
Probes belong under `--service test` and are deleted afterwards.

## Sources

| Paragraph | Evidence at `2351093` |
| --- | --- |
| Opening | `internal/keyvault/keyvault.go` (input checks vs stored-record checks); runbook `agents/skills/mac-infra/SKILL.md` |
| Same-UID limit | architecture inference: no caller authentication in `cmd/mac-keyvault/main.go`; runbook SSH agent bridge (same-UID socket statement) |
| A key is a record | `signerclient/record.go`; `internal/keyvault/record.go` ParseAddress; TestRunForeignLabelRefusedAtEntry, TestParseAddressAndLabel, TestRequireOwnLabel |
| Record contents, generations, delete | `keyvault.go` Manager.Rotate, Manager.Delete; TestManagerRotate, TestManagerDeleteGates (includes confirmed newest without version) |
| Vocabulary vs creation scope | `internal/keyvault/record.go` ValidateNew; `invariants.go` validateAlgorithm; TestValidateNew, TestValidateKind |
| Invariant table, user_presence exception | `signerclient/invariants.go` header (rev1–rev5 attribution) and recordInvariants; TestRecordInvariantsCoverEveryField |
| Where the table runs | `keyvault.go` Manager.resolve, Manager.Rotate, updateMeta, sign path; TestForgedStoredRecordRefusedEverywhere |
| Extraction refusals | `invariants.go` validateExtraction |
| Unreadable records | TestRunUnknownRecordFieldIsUnreadableEverywhere; TestDecodeRecordRefusesNestedDuplicateMembers |
| Refusal classes, JSON mode | `cmd/mac-keyvault/main.go`; TestRunJSONEnvelopeAndExitCodes, TestRunUsageErrorsAreJSONEnvelopesAndDoNotReachStore, TestManagerInitValidatesThenGatesDuplicates, TestManagerInitDuplicateRefusalIsAtomic |
| Sign gates and formats | `keyvault.go`, `signer.go`, `ecdsa.go`, runSign; TestManagerSignGates, TestForgedStoredRecordRefusedEverywhere, TestRunSignFormatsAndInterop |
| Verify order and verdicts | runVerify, `ecdsa.go`; TestRunVerifyHighSRefusedBeforeStore, TestRunVerifyVerdicts, TestRunSignVerifyRefuseBadInputBeforeStore; TestParseSignatureStrictness (parser only) |
| Not exported through these interfaces | runbook extraction paragraph and signer contract; CLI command set |
| Recovery | Manager.Delete refusal message (irreversible); Rotate copies the record |

Status: *source* and *tested* at the pin, as cited. Tests are named as
evidence of what they assert; this chapter makes no claim about a new test
run or about an installed binary.
