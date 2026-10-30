# Service KEKs: `mac-keyvault-kek` (contract kek-1)

`mac-keyvault-kek` keeps a service's 32-byte key-encryption key (KEK) wrapped
to a non-extractable P-256 key in the login Keychain. At start, the service
gets the KEK back from the broker. The broker answers only the code the
wrapped envelope is bound to. The private key never leaves Security.framework.

The broker is a separate binary from `mac-keyvault`:
- Its keys' ACLs trust only the broker.
- Building or installing it touches no existing Keychain item.
- `mac-keyvault` is not rebuilt for it.

The keys are ordinary keyvault records: kind `key`, address `SERVICE/PURPOSE`, usage `decrypt`, label
`works.relux.mac-keyvault.key.<service>.<purpose>.v<N>`.

## Pieces

| Piece | What it does |
| --- | --- |
| `mac-keyvault-kek create --address S/P [--title T] [--not-after RFC3339]` | Creates generation 1 and prints address, generation, label, fingerprint and SPKI (base64 DER). The operator posts the fingerprint; the service pins it. |
| `mac-keyvault-kek pub --address S/P [--version N]` | Prints the same for an existing generation. |
| `mac-keyvault-kek unwrap --address S/P --socket PATH` | Serves one request on a new socket, then exits. A service runs it through `kekclient.Unwrap`, never by hand. |
| `mac-keyvault-kek rebind --address S/P --socket PATH` | Serves one rebind request (below), then exits. |
| `mac-keyvault-kek audit-verify` | Checks the audit log's chain under the same framing `unwrap` requires (one complete line per entry, ending in a newline, a private regular file), and prints the entry count and the chain head. |
| `pkg/kekclient` | Go client: `Wrap` (pure Go, public key only), `Unwrap`, `Rebind`, `ParseEnvelope`, the requirement allowlist, the error codes. |

Every command disables Keychain UI first. A call that would need a dialog fails instead.

## Envelope

The service keeps one envelope file, 0600 in its private data directory.

The clear part is one JSON object:
- `format` `mac-keyvault-kek-envelope`, `v` 1;
- `address`, `generation`, `fingerprint` (base64url SHA-256 of the key's DER SPKI);
- `kcv`, the key check value: HMAC-SHA256(kek, `"mac-keyvault-kek kcv 1"`);
- `ecies`, the sealed payload. It uses Security.framework's `kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM`: an ephemeral P-256 point, the X9.63 SHA-256 KDF with the point as shared info, AES-GCM with a 16-byte IV, then point || ciphertext || tag.

The sealed payload repeats `address`, `generation`, `fingerprint` and `kcv`, and adds:
- `requirement`: the binding;
- `install_path`: where the bound service is installed;
- `kek`.

Both sides parse every contract object strictly, including nested `result`, `error` and `envelope` objects:
- exact member names, so no case aliases;
- no unknown, missing, repeated or null members;
- each member of its declared JSON type;
- exactly one object and nothing after it.

Any difference between the clear and the sealed header is refused. A KEK that does not match its `kcv` is refused as well.

The binding is inside the ciphertext, so a same-user process cannot change it without breaking GCM. It also cannot make an envelope holding the service's KEK without knowing that KEK.

**Admitted requirement form:** only `cdhash H"<40 lowercase hex>"`. The certificate-pinned form joins the allowlist when the dedicated signing identity exists.

## Unwrap

`kekclient.Unwrap(ctx, Options{Broker, SocketDir}, envelope)` takes these steps:
1. It checks that `SocketDir` is a private directory of the user.
2. It starts the broker with a fresh socket path and waits for `listening PATH`.
3. It connects, sends one request line and reads one answer line.
4. It accepts the answer only if all of these hold:
   - the answer is a contract object about the same address, generation and fingerprint;
   - the KEK is 32 bytes;
   - the KEK matches the envelope's `kcv`.

   So a substituted broker cannot hand the service a KEK of its own choosing for an unchanged envelope.

   The clear `kcv` is not authenticated. A same-user process that can both rewrite the envelope file and replace the broker can pair a chosen KEK with its own `kcv`, and `Unwrap` returns that KEK. It is not the service's real KEK, and the original KEK is not disclosed. The service's own store check (an authenticated store header) must then refuse it and stop the service. At first provisioning there is no store yet; that step happens only in a recorded window, wrapped to the posted fingerprint.

The broker runs these gates, in order:
1. **The peer's code**, from the socket's audit token (`LOCAL_PEERTOKEN`, SecCodeCopyGuestWithAttributes). It must be validly signed, with hardened runtime and library validation, and without `com.apple.security.get-task-allow`. Otherwise a same-user process could inject into it and act through it.
2. **The request:** contract `kek-1`, the operation and address this process serves, a valid envelope.
3. **The key, through keyvault's own policy:** a readable valid record, usage `decrypt`, `not_after` not passed.
4. **Decryption with the Keychain key.** Then the payload must match the clear header and the key's fingerprint.
5. **The binding:** the peer's cdhash must be the one the payload binds.
6. **The audit log.** The entry is written and synced before the answer is sent. If the log cannot be written, nothing is answered.

Pipes and inherited descriptors are not a transport: a same-user parent can keep a copy of a pipe across exec.

`Unwrap` runs the broker in its own process group and kills that group once per exchange, before it reaps the broker:
- after a protocol error or at the deadline, at once;
- after a correct answer, once the broker has exited by itself, or after one second. A broker that does not exit in that time is killed, and its answer is refused.

The broker's pid, which is also the group id, cannot be reused before it is reaped, so the signal reaches only the broker's own group. No signal is sent from another goroutine. Pipes a descendant still holds are given up after two seconds. A process that leaves the group on purpose is not contained.

### Error codes (closed set)

| Code | Meaning |
| --- | --- |
| `bad_request` | Malformed request, another contract, operation or address, an invalid envelope |
| `caller_refused` | The peer is not the bound code, or its code could be injected into |
| `envelope_invalid` | Tampered, truncated or foreign envelope; header mismatch; another key's fingerprint |
| `not_found` | No such key generation |
| `expired` | The record's `validity.not_after` has passed |
| `usage_refused` | The record lacks usage `decrypt` |
| `metadata_unknown` | The record is unreadable or invalid |
| `rebind_refused` | Rebind target missing, not hardened, or already bound |
| `unsupported_primitive` | The record's primitive cannot decrypt |
| `security` | Security.framework or audit failure |

A client treats any other code, or any answer that is not a contract object, as `ErrProtocol`.

## Rebind

A service reinstall changes its cdhash. The bound service (still the old binary) calls `kekclient.Rebind`. The broker then:
1. checks the caller as for unwrap;
2. reads the code at the envelope's `install_path` itself; it must be a regular file, validly signed with hardened runtime and library validation, without get-task-allow, and not the code already bound;
3. re-seals the same KEK under `cdhash H"<that file's cdhash>"`.

The new envelope comes back; the KEK never does. The audit log records the new binding.

## Service-side requirements

- Sign with `codesign --options runtime,library` and no get-task-allow.
- Have no command, flag or environment switch that prints, exports or re-wraps the KEK, or writes decrypted store contents to a path the caller chooses. A same-user process can run a byte-identical copy of the bound binary with its own arguments, and the broker answers it. Test that the shipped CLI has no such path.
- Fail closed: an unwrap error, an `ErrProtocol` answer or an unreadable store stops the service. It never generates a new KEK or starts an empty store by itself. A fresh KEK is made only in a recorded install window.
- At the switch from a pilot key file:
  1. generate a fresh KEK;
  2. wrap it to the posted fingerprint;
  3. check one unwrap round trip;
  4. delete the pilot key and the pilot store. They are not migrated.

## Limits

- Everything runs as one macOS user, so this is a barrier against casual and accidental use, not a wall. A separate OS user for the service is the real isolation.
- The binding is to code, not path. Any same-user process can rebind to any binary it can place at the install path and then start the bound service's rebind. Detection is the control: the audit log, plus the chain head posted in each window record and compared at checkpoints.
- The audit chain shows an edit inside the log. A same-user rewrite of the whole log passes its own chain, so compare the head with the posted one.
- The broker is ad-hoc signed. A rebuilt broker is a new code identity, and with UI disabled the key's ACL refuses it silently. `scripts/setup.sh` therefore builds `mac-keyvault-kek` only when it is absent, and keeps an installed `~/.local/bin/mac-keyvault-kek` that names another checkout's broker or is a regular file. `--rebuild-kek` is for a planned owner sitting that also re-provisions the keys. With a stable signing identity this goes away.
- The key is non-extractable. If the login Keychain is reset or the item is deleted, the envelope cannot be opened again. A service using this must be able to rebuild its store, or keep a recovery envelope elsewhere.
- First provisioning trusts the public key the operator reads with `create` or `pub`. The service wraps only to the fingerprint posted with the window record.
- The envelope file and the broker binary are same-user files. Rewriting both lets a process feed the service a KEK of its choice (not the real one). Only the service's authenticated store refuses it, so a service must never start a new store on its own after an unwrap.

## Tests

- `pkg/kekclient`:
  - envelope round trip;
  - tamper and foreign-key refusal;
  - strict parsing;
  - requirement allowlist;
  - check value;
  - client refusals of answers outside the contract, including a broker that answers a KEK of its choice.
- `internal/keyvault/kek`: the broker over keyvault's Manager with an in-memory backend:
  - bound caller answered;
  - other or injectable callers refused;
  - tampered, foreign or mismatched envelopes refused;
  - missing, expired and unusable keys refused;
  - malformed requests;
  - no answer without the audit log;
  - rebind and its refusals;
  - the audit chain.
- `TestCodeInspectorReadsSignatures` checks the real inspector against binaries signed by codesign in four variants, and against a changed binary and a symlink.
- `TestSecurityStoreDecryptOpensGoEnvelope` opens a Go-sealed envelope with a real non-extractable Keychain key and refuses tampered ones. Like every real-Keychain test, it runs only in an attended sitting.
