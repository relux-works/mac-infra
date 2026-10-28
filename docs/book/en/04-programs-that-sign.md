# 4. Programs that sign

A program requesting several signatures must know that every answer belongs
to its request and the key it selected.
Running a separate CLI command for each signature leaves the program to
coordinate those answers itself.
How does a consumer keep that association through malformed replies and key
rotation?
This chapter follows signer contract 1 from session startup to result
validation.
Record policy and store protection remain the subjects of chapters 2 and 3.
The repository supplies a Go consumer in `signerclient` (*source*:
`internal/keyvault/signerclient/client.go`, `Start`, `Client.Call`).
Commands belong in the [signer runbook](../../../agents/skills/mac-infra/SKILL.md#signer-contract-for-kvctl-signer-serve-contract-1).

## Bind a generation before requesting work

`mac-keyvault signer serve --address <service>/<purpose>` selects one
address for a stdin/stdout session.
The server resolves the address and writes a hello before reading requests.
Its result names the tool, tool version, address, kind, generation, label,
fingerprint and four operations: `describe`, `pub`, `sign`, `verify`.
Subsequent nonblank input lines receive individual responses in order.
Blank lines are ignored, and ordinary EOF ends the command with exit 0.
A startup refusal instead produces a failed hello and a nonzero exit.
Transport errors can terminate serving.
(*source*: `internal/keyvault/signer.go`, `SignerServer.Serve`;
`cmd/mac-keyvault/main.go`, `runSigner`.)

Omitting `--version` selects the newest generation at hello time.
The server then passes that resolved generation to every operation.
In `TestSignerServePinsGenerationAcrossRotate`, rotation after hello leaves
all four operations answering with generation 1 and its fingerprint.
A new unpinned session selects generation 2.
Binding does not keep a deleted key available:
`TestSignerServeNotFoundMidStream` removes the bound item after hello and
requires `not_found` for signing and verification.
Choose a new session deliberately when adopting a rotated key.
(*tested*: those two tests in `internal/keyvault/signer_test.go`.)

Each request needs a string or numeric `id` and an operation from the hello.
The server reads the raw object before decoding its typed request.
It checks the ID, operation and allowed member names in that order.
For example, `allow_high_s: false` on `sign` is `bad_request` because
`sign` does not accept that member.
An empty or false value cannot make an unwanted parameter disappear.
Signing still enters the manager's record and policy gates from chapter 2.
(*source*: `internal/keyvault/signer.go`, `SignerServer.handle`,
`requireMembers`, `SignerServer.sign`; `internal/keyvault/keyvault.go`,
`Manager.SignIf`.)

## Keep refusals distinguishable from protocol failures

A consumer can continue after a declared remote error, but must stop when
the server's reply violates the contract.
`ErrorContract` has 21 rows marked `Stream`, counted at this chapter's pin.
`StreamErrorCodes` derives the closed set from those rows.
It includes malformed-request codes, policy refusals and operational
failures such as `security`.
The client returns declared remote errors as `*signerclient.Error`.
An undeclared code becomes `ErrProtocol`, kills the server and leaves the
client unusable.
Continuing the session does not imply that retrying the same request will
succeed.
(*source*: `internal/keyvault/signerclient/codes.go`, `ErrorContract`,
`StreamErrorCodes`; *tested*: `TestClientFailsClosedOnUndeclaredErrorCode`.)

The golden corpus pins response bytes, including member order and error
text, rather than merely checking that JSON parses.
The corpus contains 92 response fixtures, including 12 CLI-startup fixtures;
58 responses carry errors, covering all 21 stream codes.
`TestSignerServeGoldenWire` compares server output against recorded lines
using a canned backend and fixed clock.
`TestRunSignerServeStartupGolden` compares startup output and exits through
the CLI entry.
`TestSignerGoldenCoversStreamErrorCodes` checks coverage in both directions.
`TestSignerStreamCodesEmittedByProduction` separately provokes each declared
code through production dispatch.
These are assertions about the supplied cases, not exhaustive backend
coverage.
(*tested*: those four tests; *source* for the corpus enumeration:
`internal/keyvault/signertest/golden.go`, `Load`, `ErrorCodes`.)

## Judge the line before trusting the answer

A missing `ok` must not become the Go boolean zero value, and `error: null`
must not become an absent error.
`decodeEnvelope` checks raw member presence and JSON type before constructing
a `Response`.
Replies require a non-null string or numeric ID.
Present results and errors must be objects.
Errors require string `code`, `message` and `hint`, with optional numeric
`os_status`.
Success requires a result without an error; only documented verification
refusals may carry both.
The 47 rows of `TestClientRefusesEnvelopeMissingOrNullMembers` include
accepted controls and rejected shapes at startup and during calls.
(*source*: `internal/keyvault/signerclient/envelope.go`, `decodeEnvelope`;
`internal/keyvault/signerclient/client.go`, `checkEnvelope`; *tested*:
`TestClientRefusesEnvelopeMissingOrNullMembers`.)

Duplicate names need detection before a map or struct discards an earlier
value.
`DecodeObject` first runs `CheckDocument`, which walks every object and array
and compares decoded member names.
Thus `contract` and `co\u006etract` repeat the same name.
`TestClientRefusesDuplicateMembers` exercises repeats in envelopes, errors,
hello results and operation results, including nested record objects and
array entries.
The server uses the same reader and answers duplicate request members with
`bad_request` under `id: null`.
(*source*: `internal/keyvault/signerclient/object.go`, `DecodeObject`,
`CheckDocument`; `internal/keyvault/signer.go`, `SignerServer.handle`;
*tested*: `TestClientRefusesDuplicateMembers`.)

An accepted shape still needs the right identity.
`Start` checks contract 1 and requires the requested address and kind,
`mac-keyvault` as tool, a positive generation matching any explicit version,
nonempty label and fingerprint, and the four operations in contract order.
`Client.call` then compares each response ID with its pending request.
These checks establish consistency with the hello.
They do not compare its fingerprint with an independently configured
fingerprint; that comparison belongs to the consumer.
(*source*: `internal/keyvault/signerclient/client.go`, `Start`, `checkHello`,
`Client.call`, `Options`.)

Before the first signing or verification call without a cached public key,
the client requests `pub`.
`checkPub` parses the requested SPKI representation as P-256 and checks its
fingerprint against the hello.
`checkSign` requires the hello identity, SHA-256, the requested digest and
any explicitly requested format.
It checks that hexadecimal and base64 signatures encode identical bytes,
requires low S and verifies the signature under that public key.
With no explicit signing format, it accepts either supported format rather
than independently confirming the record's default.
(*source*: `internal/keyvault/signerclient/client.go`, `Client.Call`;
`internal/keyvault/signerclient/result.go`, `checkPub`, `checkSign`;
*tested*: `TestClientRefusesResultNotBoundToRequestOrHello`.)

For verification, the client checks the digest, format and `allow_high_s`
relationship, then re-derives ordinary true and false verdicts with
`crypto/ecdsa` under the hello key.
There is a deliberate exception: `high_s_refused` carries a partial verdict
without label or fingerprint.
The server produces it before reading the key, and the client checks the
signature's high-S condition rather than its validity under that key.
(*source*: `internal/keyvault/signer.go`, `SignerServer.verify`;
`internal/keyvault/signerclient/result.go`, `checkVerify`; *tested*:
`TestClientRefusesResultNotBoundToRequestOrHello`.)

`describe` binds the record's address, kind, generation, label and fingerprint
to the hello and applies the shared schema-2 invariant table.
An invalid record may still be described when its finding reports the
matching invariant failure.
The consumer must inspect findings before using the key.
The client checks operation-entry shape, but leaves primitive derivation
and the expiry clock judgment to the server.
(*source*: `internal/keyvault/signerclient/result.go`, `checkDescribe`;
*tested*: `TestClientRefusesResultNotBoundToRequestOrHello`.)

For a certificate-producing program, `CryptoSigner` adapts the session to
Go's `crypto.Signer`, accepting SHA-256 digests and requesting DER low-S
signatures.
`TestTypedCallsAgainstFake` checks a self-signed certificate made through
that adapter and rejects SHA-512 options and a short digest.
The runbook proposes this route for kvctl's `macos-keychain` backend.
kvctl does not exist as code at this pin; the demonstrated consumer is the
repository's Go client, not a live kvctl integration.
(*source*: `internal/keyvault/signerclient/client.go`, `CryptoSigner`,
`cryptoSigner.Sign`; `agents/skills/mac-infra/SKILL.md`, “Signer contract
for kvctl”; *tested*: `TestTypedCallsAgainstFake`; kvctl: *proposed*.)

## What this does not protect against

A session does not authenticate which agent or same-user process requested
the signature.
Neither startup nor request handling checks a caller identity.
This is the same-user limit from chapter 2, inferred from those paths;
store enforcement remains a separate boundary discussed in chapter 3.
Use the contract to reject inconsistent answers, and compare the hello
fingerprint with independently trusted configuration before authorizing
signing.
(*source*: `cmd/mac-keyvault/main.go`, `runSigner`;
`internal/keyvault/signer.go`, `SignerServer.handle`;
`internal/keyvault/signerclient/client.go`, `Options`, `checkHello`.)

**Status.** Source checked at `88c6c01f3f1755c80b0e2a806a85dbe1a3f6da1e`,
the job's later pin.
*Tested* identifies assertions read, not a fresh test run.
Counts above come from read-only enumeration.
The package contains 15 test functions plus its `TestMain` harness.
No installed-state claim is made; kvctl remains *proposed*.

## Sources

| Paragraph | Repository-relative path and function or symbol | Test asserting the stated case |
| --- | --- | --- |
| Opening | `internal/keyvault/signerclient/client.go`: `Start`, `Client.Call` | Source only |
| Session and hello | `internal/keyvault/signer.go`: `SignerServer.Serve`; `cmd/mac-keyvault/main.go`: `runSigner` | Source only |
| Rotation and disappearance | `internal/keyvault/signer.go`: `pinGeneration`, `SignerServer.sign`, `SignerServer.verify` | `internal/keyvault/signer_test.go`: `TestSignerServePinsGenerationAcrossRotate`, `TestSignerServeNotFoundMidStream` |
| Request gates | `internal/keyvault/signer.go`: `handle`, `requireMembers`, `sign`; `internal/keyvault/keyvault.go`: `Manager.SignIf` | Source only |
| Closed refusals | `internal/keyvault/signerclient/codes.go`: `ErrorContract`, `StreamErrorCodes`; `internal/keyvault/signerclient/client.go`: `checkEnvelope`, `Client.fail` | `internal/keyvault/signerclient/client_test.go`: `TestClientFailsClosedOnUndeclaredErrorCode` |
| Golden fixtures | `internal/keyvault/signertest/golden.go`: `Load`, `ErrorCodes`; `internal/keyvault/testdata/signer-v1/` | `internal/keyvault/signer_test.go`: `TestSignerServeGoldenWire`, `TestSignerGoldenCoversStreamErrorCodes`; `cmd/mac-keyvault/signer_golden_test.go`: `TestRunSignerServeStartupGolden`, `TestSignerStreamCodesEmittedByProduction` |
| Raw envelopes | `internal/keyvault/signerclient/envelope.go`: `decodeEnvelope`; `internal/keyvault/signerclient/client.go`: `checkEnvelope` | `internal/keyvault/signerclient/client_test.go`: `TestClientRefusesEnvelopeMissingOrNullMembers` |
| Duplicates | `internal/keyvault/signerclient/object.go`: `DecodeObject`, `CheckDocument`; `internal/keyvault/signer.go`: `handle` | `internal/keyvault/signerclient/contract_test.go`: `TestClientRefusesDuplicateMembers` |
| Hello and response identity | `internal/keyvault/signerclient/client.go`: `Start`, `checkHello`, `Client.call`, `Options` | Source only |
| Public key and signing | `internal/keyvault/signerclient/result.go`: `checkPub`, `checkSign`; `internal/keyvault/signerclient/client.go`: `Client.Call` | `internal/keyvault/signerclient/contract_test.go`: `TestClientRefusesResultNotBoundToRequestOrHello` |
| Verification exception | `internal/keyvault/signer.go`: `verify`; `internal/keyvault/signerclient/result.go`: `checkVerify` | `internal/keyvault/signerclient/contract_test.go`: `TestClientRefusesResultNotBoundToRequestOrHello` |
| Description and findings | `internal/keyvault/signerclient/result.go`: `checkDescribe` | `internal/keyvault/signerclient/contract_test.go`: `TestClientRefusesResultNotBoundToRequestOrHello` |
| Certificate adapter and proposal | `internal/keyvault/signerclient/client.go`: `CryptoSigner`, `cryptoSigner.Sign`; `agents/skills/mac-infra/SKILL.md`: signer section | `internal/keyvault/signerclient/client_test.go`: `TestTypedCallsAgainstFake` |
| Same-user limit | `cmd/mac-keyvault/main.go`: `runSigner`; `internal/keyvault/signer.go`: `handle`; `internal/keyvault/signerclient/client.go`: `Options`, `checkHello` | Source inference |
| Status | Job pin; `internal/keyvault/signerclient/*_test.go`: `Test*` declarations | Assertions read; no tests run |
