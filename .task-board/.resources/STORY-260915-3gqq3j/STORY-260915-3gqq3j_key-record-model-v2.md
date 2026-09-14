# Key record model v2 (owner decision 2026-09-15, consolidated)

Every vault item is a record, not a bare label. The record is stored as JSON in
`kSecAttrApplicationTag` of the Keychain item so it cannot drift from the item
on delete/rotate; there are no sidecar files.

## 1. Identity and addressing

| Element | Rule |
| --- | --- |
| Uniqueness | `(kind, service, purpose, version)` |
| Label | `works.relux.mac-keyvault.<kind>.<service>.<purpose>.v<N>` \u2014 `.v<N>` is always present, v1 included |
| `kind` | `key` (private pair), `public-key` (imported peer SPKI, no private half), `certificate` (X.509), `secret` (symmetric or opaque material) |
| `service` | consumer of the item: `kvctl`, `bsim-ci`, `agent`, \u2026 |
| `purpose` | role of the item inside that service: `pki-root`, `pki-intermediate`, `attest`, `api-token`, \u2026 |
| Charset | `service`, `purpose`: `[a-z0-9-]+`, 1\u201340 chars |
| CLI address | `<service>/<purpose>` plus `--kind` (default `key`; certificate commands default to `certificate`); without `--version N` the address resolves to the highest version |
| Prefix guard | every command resolves the address into the full label and refuses any label outside `works.relux.mac-keyvault.` before any Security call; a caller cannot supply a raw label |

A key and its certificate deliberately share `service/purpose`; `kind` keeps
them apart.

## 2. Record (schema 2)

```json
{
  "schema": 2,
  "kind": "key",
  "service": "kvctl",
  "purpose": "pki-root",
  "version": 1,
  "title": "bsim test PKI root",
  "description": "Root of the throwaway test PKI used by kvctl integration runs",
  "algorithm": "ec-p256",
  "store": "keychain",
  "extraction": "none",
  "usages": ["sign"],
  "format": { "public": "spki-der", "signature": "ecdsa-der-low-s" },
  "created": "2026-09-15T13:50:00+03:00",
  "origin": { "user": "alexis", "host": "macbook", "tool": "mac-keyvault/0.1.0", "source": "generated" },
  "issuer": null,
  "validity": { "not_before": null, "not_after": null },
  "meta": { "owner": "alexis", "pki": "bsim-test", "ticket": "EPIC-260915-1g0e1c" }
}
```

| Field | Values | Rule |
| --- | --- | --- |
| schema | 2 | a v1 tag (`mac-keyvault/1 store=\u2026 created=\u2026`) is read as `schema: 1` with service/purpose `unknown`; never upgraded silently |
| kind | key, public-key, certificate, secret | see \u00a71 |
| service, purpose | see \u00a71 | required |
| version | integer \u2265 1 | the epoch: `rotate` creates `version+1` and keeps the old item until `delete` |
| title | \u2264 80 chars, optional | human name, shown in `list`; never used for lookup |
| description | free text, optional | shown in `describe` and `list --json`; never used for lookup |
| algorithm | `ec-p256` (key, public-key, certificate); `aes-256-gcm`, `opaque` (secret); `ec-p384`, `rsa-3072` reserved; `ed25519` refused explicitly (no SecKey support) | never mapped silently to another algorithm |
| store | keychain, enclave | enclave refuses with -34018 on an unprovisioned binary and never falls back |
| extraction | none (default), human, agent | export policy, fixed at creation (\u00a74) |
| usages | sign, verify, wrap, encrypt, decrypt, attest | policy gates for operations (\u00a76) |
| format | `{public, signature, envelope}` subset | defaults for output representation; a command flag overrides; keys allowed per kind: key/public-key \u2192 public, signature; certificate \u2192 public (x509-der, x509-pem, pkcs7-chain); secret \u2192 envelope (json, der); any other key refused |
| created | RFC3339 | when the vault created or imported the item |
| origin | `{user, host, tool, source}` | who put it in the vault and how: `source` = `generated` or `imported:<sha256 of the imported bytes>`; set by the vault, never user-supplied |
| issuer | certificate: `{dn, fingerprint}` from X.509; otherwise null | who signed the certificate |
| validity | `{not_before, not_after}` RFC3339 or null | certificate: copied from X.509; key/secret: null unless `--not-after` is given, then sign/decrypt refuse after it |
| meta | free map string \u2192 string, number, or bool | consumer-owned; reserved names refused: every top-level field above plus `label`, `fingerprint`, `exposure`, `operations` |

Derived on every read, never stored: `label`, `fingerprint`, `exposure`,
`operations`.

### Decision: fingerprint vs checksum (owner 2026-09-15)

| Kind | `fingerprint` | Rationale |
| --- | --- | --- |
| key, public-key, certificate | SHA-256 of the SPKI DER, base64url, always shown | a public key is public; its fingerprint is the natural identifier and there is nothing to protect |
| secret | `null`, always | a hash of secret material is an oracle (offline guessing of low-entropy tokens/passwords); the vault never derives an identifier from the material |

When a secret needs an identifier for reconciliation, the consumer puts an
explicit `meta.checksum` there at `init` (any string; the vault neither
computes nor validates it). This is the one place where the model deliberately
refuses to derive a field, and the choice is the consumer's, not the vault's.

## 3. Model vs meta (the split rule)

A field belongs to the model when the vault reacts to it (lookup, gates,
defaults) or derives it from the item (algorithm, store, created, origin,
issuer, fingerprint). A field belongs to `meta` when the vault only carries it
for a consumer (owner, pki name, ticket, environment, rotation hints).
`title`/`description` are model fields because every record has them and
`list` renders them. If a meta field ever starts to drive behaviour it moves
into the model with a schema bump; it never stays "by convention" in the map.

## 4. Access policy

Two independent properties:

- **exposure** (derived from the registry row, \u00a75): where the material is
  while an *operation* runs. `never` \u2014 Security.framework performs the
  operation and the private material never leaves Keychain/Secure Enclave.
  `process` \u2014 the material is loaded into the `mac-keyvault` process for one
  operation, zeroed afterwards, and is not written or printed by that
  operation.
- **extraction** (stored, chosen at `init`): who may *export* the material.

| extraction | Who can export | Keychain shape | Allowed kinds |
| --- | --- | --- | --- |
| none | nobody, ever | `kSecAttrIsExtractable=false`; Secure Enclave items are always `none` | key, secret |
| human | a human: `--human-authorized` + the Keychain passphrase dialog | extractable, split SecAccess ACL: use authorizations trust the calling binary (no prompt); export authorizations (`kSecACLAuthorizationExportClear/ExportWrapped`) trust no application and require the passphrase every time | key, secret |
| agent | the agent, no prompt | extractable, use and export trusted to the calling binary | secret; **key only on an explicit human instruction** |

`init` has no default other than `none`; `--extraction agent` must be typed
literally so the transcript shows the choice. The agent never selects `agent`
for a key on its own; the SKILL.md states this as a contract. `describe`/`list`
show `extraction` so a later reader sees when a private key is not vault-bound.

The only hard boundary is private/secret material leaving the vault:

| Agent, no prompt, no special flag | Human only (`--human-authorized` + passphrase) |
| --- | --- |
| init, list, describe, rotate, meta get/set/unset, delete --confirm | export-private / export-secret of an item with extraction `human` |
| sign, verify, encrypt, decrypt | |
| pub / export of public keys and certificates in every representation | |
| import of public keys and certificates | |
| export-private / export-secret of an item with extraction `agent` | |

Items with extraction `none` have no path at all, human or agent. Agents never
pass `--human-authorized`; the flag exists so a transcript shows unambiguously
when a human chose to extract.

## 5. Primitive registry (architecture rule)

`internal/keyvault` keeps one registry: `(kind, algorithm, store) \u2192 {exposure,
operations[]}`. `describe`, `list`, the operation gates, and the CLI help are
all driven from it. Adding a primitive (a curve, RSA, a symmetric algorithm, a
certificate type) means adding one registry row plus its backend
implementation; no command grows a special case. A record whose row does not
exist is reported with `operations: []` and an `unsupported_primitive` finding,
never guessed.

| Row (kind, algorithm, store) | exposure | Supported operations |
| --- | --- | --- |
| public-key, ec-p256, keychain | never | ecdsa-sha256-verify, ecies-p256-encrypt, export-public |
| certificate, ec-p256, keychain | never | the public-key set + export-certificate, verify-chain (reserved) |
| key, ec-p256, keychain | never | the public-key set + ecdsa-sha256-sign, ecies-p256-decrypt, ecdh-p256, export-private |
| key, ec-p256, enclave | never | as keychain minus export-private; creation refused until a provisioned binary exists |
| secret, aes-256-gcm, keychain | process | aes-256-gcm-encrypt, aes-256-gcm-decrypt, export-secret |
| secret, opaque, keychain | process | export-secret |

T1 implements exactly the `key, ec-p256, keychain` row; the rest arrive with
T4\u2013T7.

## 6. Derived: operations

Every read (`list --json`, `describe`, `pub --json`) returns `operations`: the
registry set for the row intersected with policy:

| Operation | Requires |
| --- | --- |
| ecdsa-sha256-sign | usages \u220b sign; validity.not_after unexpired |
| ecies-p256-decrypt, aes-256-gcm-decrypt | usages \u220b decrypt; validity unexpired |
| ecdh-p256 | usages \u220b wrap |
| ecdsa-sha256-verify, ecies-p256-encrypt, aes-256-gcm-encrypt, export-public, export-certificate | always, for a readable public half / secret |
| export-private, export-secret | extraction \u2260 none (`human` adds `human_authorized: true` to the entry) |

Each entry: `{name, input, output, via}`; `via` is the CLI command
(`reserved` = not implemented yet, so a consumer never assumes it works).

```json
"operations": [
  { "name": "ecdsa-sha256-sign",   "input": "sha256-digest",           "output": "ecdsa-der-low-s|ecdsa-raw",              "via": "sign" },
  { "name": "ecdsa-sha256-verify", "input": "sha256-digest+signature", "output": "verdict",                                "via": "verify" },
  { "name": "ecies-p256-encrypt",  "input": "payload",                 "output": "envelope:ecies-x963-sha256-aesgcm",      "via": "reserved" },
  { "name": "export-public",       "input": null,                      "output": "spki-der|spki-pem|jwk",                  "via": "pub" }
]
```

Payload operations accept any bytes (`--data-file`, `--stdin`, `--data-hex`)
and return an envelope `{alg, nonce, aad, ciphertext, tag}` as JSON or DER;
raw ciphertext without its parameters is never emitted. kvctl selects an
operation by `name`/`input`/`output`, never by guessing from `algorithm`.

## 7. Generation and import

The vault mints (generates) primitives itself, and it also imports existing
ones so that live PKI roots and tokens can move into the vault. Imported
material obeys the same `extraction` policy as generated material: imported
with `none`, it is vault-bound from that moment on.

`init` is the generator for each registry row:

| Command | Backend |
| --- | --- |
| `init --kind key --algorithm ec-p256` | SecKeyCreateRandomKey |
| `init --kind secret --algorithm aes-256-gcm` | SecRandomCopyBytes, 32 bytes |
| `init --kind secret --algorithm opaque --generate token:N \| password:N[:charset] \| bytes:N` | SecRandomCopyBytes, encoded per generator |
| `cert self-sign <s>/<p> --subject \u2026 --days N`, `csr <s>/<p> --subject \u2026` (T4) | signed through the vault; private key never leaves |

Generated material is written straight into the Keychain item under the
record's `extraction` policy and is echoed only by an `export-*` that policy
allows.

`import` (T4 public kinds, T8 private kinds) takes the same record flags as
`init` plus the input:

| Command | Input | Backend |
| --- | --- | --- |
| `import --kind key --in FILE \| --stdin` | PKCS#8 DER/PEM (unencrypted, or `--passphrase-stdin`) | SecItemImport into the login keychain with `kSecAttrIsExtractable` per `--extraction`; algorithm detected from the key and validated against the registry |
| `import --kind secret --stdin [--algorithm aes-256-gcm\|opaque]` | raw bytes or text on stdin only \u2014 never argv, so the value does not appear in `ps` or shell history | Keychain secret item |
| `import --kind public-key --in FILE` | SPKI DER/PEM | public SecKey item |
| `import --kind certificate --in FILE` | X.509 DER/PEM | SecCertificate item |

### Import detection

`--kind` is optional on `import`: the CLI detects the kind, algorithm and
representation from the input itself; only `--service`/`--purpose` are
mandatory because the vault never guesses what an item is for.

| Input | Detection | Result |
| --- | --- | --- |
| PEM `PRIVATE KEY` / `EC PRIVATE KEY` | header + PKCS#8/SEC1 parse | `key`, algorithm from the key |
| PEM `ENCRYPTED PRIVATE KEY` | header | `key`; requires `--passphrase-stdin` |
| PEM `PUBLIC KEY` | header + SPKI parse | `public-key` |
| PEM `CERTIFICATE` (one or many) | headers | one `certificate` record per block; a chain is linked by issuer |
| DER without PEM | ASN.1 probes in order: PKCS#8 \u2192 SPKI \u2192 X.509 \u2192 PKCS#7 \u2192 PKCS#12 | the matching kind |
| PKCS#12 | magic + parse, passphrase on stdin | two records, `key` and `certificate`, under the same service/purpose |
| nothing parses | \u2014 | refused (`unrecognized_format`) unless `--as-secret` is given, then `secret`/`opaque` |

The vault never guesses between "a key in a format I do not know" and "an
opaque secret"; that is the one decision left to the caller. An explicit
`--kind` that contradicts the detection is refused, not trusted.

`origin.source` = `imported:<sha256 of the input bytes>`, `created` = the
import time. Any agent may import without a prompt: the material was already
outside the vault, and importing only narrows its exposure. The vault never
deletes the source file; after a successful private import it prints
`source_still_on_disk: PATH` and leaves that decision to the human.

## 8. CLI

- `init --service S --purpose P [--kind key] [--algorithm A] [--title T] [--description D] [--usages a,b] [--format-public F] [--format-signature F] [--format-envelope F] [--extraction none|human|agent] [--not-after RFC3339] [--meta k=v]\u2026 [--meta-json FILE] [--generate SPEC]`
- `list [--service S] [--kind K] [--json]` \u2014 text: label, kind, algorithm, store, extraction, usages, created, fingerprint, title
- `describe <s>/<p> [--kind K] [--version N]` \u2014 full record + derived fields
- `pub <s>/<p> [--out FILE] [--format spki-der|spki-pem|jwk]`
- `export <s>/<p> --kind certificate [--format x509-der|x509-pem|pkcs7-chain]` and `convert` for files (T4)
- `sign`, `verify` (T2); `encrypt`, `decrypt` (T5/T6); `import` (T4 public kinds, T8 private kinds)
- `meta get|set|unset <s>/<p> [key] [value]`
- `rotate <s>/<p>` \u2014 new version with the same record (meta, usages, format, extraction, title, description copied); refused when the current record is unreadable or `schema: 1`
- `delete <s>/<p> --confirm [--version N]`
- `export-private <s>/<p> --out FILE [--format pkcs8-der|pkcs8-pem|pkcs12] [--human-authorized]` and `export-secret <s>/<p> --out FILE [--human-authorized]` \u2014 per \u00a74
- `--json` on every command: `{ok, command, result|error{code, message, hint, os_status}}`; exit 0 ok, 1 failure, 2 usage, 3 policy refusal; usage errors in `--json` mode still produce the envelope

### Error contract

Every refusal or failure carries a stable machine `code`, a one-line human
`message` that says what was wrong in the caller's terms, and a `hint` that
says what to do next. Raw OSStatus numbers never appear alone: `os_status` is
attached, and the message translates it. Text mode prints
`error: <code>: <message>` and `hint: <hint>` to stderr.

| code | exit | when | hint shape |
| --- | ---: | --- | --- |
| usage | 2 | bad flags/args | the exact usage line |
| foreign_label | 3 | address resolves outside the vault prefix | "addresses are <service>/<purpose>; raw labels are not accepted" |
| not_found | 1 | no record for address/kind/version | nearest existing versions or kinds, if any |
| duplicate | 3 | (kind, service, purpose, version) exists | "use rotate to create the next version, or --version" |
| kind_mismatch | 3 | `--kind` contradicts import detection | the detected kind |
| unrecognized_format | 3 | import input matches nothing | "if this is an opaque secret, re-run with --as-secret" |
| passphrase_required | 3 | encrypted PKCS#8 / PKCS#12 without `--passphrase-stdin` | the flag to add |
| missing_entitlement | 1 | Security returned -34018 (enclave / data-protection keychain) | "this binary is not signed with a provisioning profile; use the login keychain store" |
| extraction_refused | 3 | export against `none`, or `human` without `--human-authorized`, or enclave | which policy applies to this record |
| usage_refused | 3 | operation not in `usages` | the usages the record has |
| expired | 3 | validity.not_after passed | the timestamp |
| unsupported_primitive | 1 | no registry row for the record | the row tuple |
| security | 1 | any other Security.framework failure | the OSStatus name and the command that failed |

## 9. Negative expectations (every task adds its rows)

- init: missing service/purpose, invalid chars, unknown kind/algorithm/usage/format/extraction, `format` key not allowed for the kind, reserved name inside meta, meta value of unsupported type, `--generate` with kind \u2260 secret, `--extraction agent` with kind key **without** the literal flag (i.e. any default path): refused before any Security call
- duplicate `(kind, service, purpose, version)`: refused atomically across processes
- any address that resolves outside the prefix, or a raw label in place of an address: refused before any Security call, exit 3
- rotate with unreadable record or `schema: 1`: refused, never guesses store or policy
- sign without usages sign, or after not_after: refused, exit 3
- decrypt without usages decrypt: refused, exit 3
- export-private/export-secret with extraction none, or human without `--human-authorized`: refused, exit 3; enclave keys: refused always
- `--json` usage errors: envelope on stdout, empty stderr, exit 2, no backend call
- import: unrecognized input without `--as-secret` refused; `--kind` contradicting detection refused; malformed PKCS#8/SPKI/X.509 refused before any Security call; algorithm outside the registry refused; a private key or secret supplied via argv instead of file/stdin refused; the source file is never modified or removed
- private key of an extraction-none item cannot be exported by any Security API (executable proof), and the SecAccess trusted-application set is exactly the calling binary
