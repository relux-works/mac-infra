# Generic-password ownership: mac-tool-secret

`mac-tool-secret` never reads, prints or transfers secret values. It has no
item-data operation. It inventories generic-password metadata, binds an
existing item in place, and verifies its plaintext-release ACL structure.
SecKey/mac-keyvault items are outside its scope.

Implementation state: inventory, structural verify and the separate probe are
implemented and tested, with priority over bind. Bind is implemented on the same branch behind
the owner-presence gate; its real authorization/mutation path remains
**not yet exercised**. It is not accepted for real-item migration.

Build/install with `scripts/setup.sh --only mac-tool-secret` from the admitted
release clone. This also builds `mac-tool-secret-probe`; the two executables
are signed separately with distinct ad-hoc identities. Neither is admitted as
a secret owner. They are independent of the keyvault rebuild guard. Requires
macOS with cgo and the Xcode/Command Line Tools SDK.

## Inventory scope and local full listings

```sh
mac-tool-secret inventory --keychain /absolute/test.keychain-db --json
mac-tool-secret inventory --keychain /absolute/test.keychain-db --service-prefix works.relux. --json
mac-tool-secret inventory --keychain /absolute/test.keychain-db --all --owner-sitting --out /absolute/new/private-inventory.json --json
```

Default output includes only services prefixed `works.relux.` or `a2a`, plus
exact service `Claude Code-credentials`. The Claude token service
`works.relux.claude.oauth-token` is included in the first prefix.
`--service-prefix` further narrows that scope; it cannot widen it. Full
inventory requires `--all`, `--owner-sitting`, TTYs on both stdin/stdout, no
`TMUX` or `STY` environment variable, and an absolute `--out` path. Its output
is written exclusively to a new local `0600` file: no full listing on stdout,
even in JSON mode. Existing files and symlink destinations are refused.

Omitting `--keychain` uses the user's normal keychain search list. Development
and validation must always specify a disposable keychain. No real
login/ios-signing keychain or production item was used to validate this tool.

Inventory reports service, account, label, creator, partition lists and every
ACL entry whose authorizations include **decrypt, export_clear,
export_wrapped or any**. Each entry includes its plaintext authorizations and
the trusted paths/requirements captured at trust time. Findings include
`generic_reader`, `weak_requirement`, `team_ou_forgeable`, `unverified`,
`requirement_unknown`, `any_application`, `partition_mismatch`, and heuristic
`rollback_leftover` (generic-reader grants on rollback/backup/migration/old
names). Both `apple:` and `apple-tool:` always flag `partition_mismatch`.

Inventory also reports `writer_acls` and per-entry `writers` findings for
`item_modify`, `item_delete`, `delete`, `change_acl`, `change_owner`, `encrypt` and wildcard
`any` authorizations. Each writer includes its stored applications and a
`foreign_writer` verdict. A non-owner or unrestricted writer is flagged, and
verify fails on `foreign_writer` even when plaintext readers are correct.
Unreadable writer subjects or stored requirements fail closed. An empty
explicit trusted list requires a system authorization dialog and is not an
automatic foreign grant; a NULL list grants any application and is flagged.
Inventory infers an owner only from one unambiguous certificate-pinned reader
requirement; writers cannot establish their own ownership. Unknown/ambiguous
ownership flags nonempty writer grants conservatively. Verify instead compares
them with its explicitly validated `--owner` requirement.
`encrypt` is included because secure-storage blob modification uses the
group key to encrypt replacement data; this is a writer operation, although
it cannot release plaintext. See Apple's [secure-storage implementation](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_cdsa_client/lib/securestorage.cpp)
and [encryption authorization check](https://github.com/apple-oss-distributions/Security/blob/main/securityd/src/localdatabase.cpp).

Inventory infers a team from pinned stored requirements and also compares the
partition with a currently validated owner whose DR is unchanged. This detects
option-B rebuilds' changed cdhash partitions without replacing classification
of stale stored requirements with the current binary's DR. Missing/changed
binaries cannot establish a partition match; absence of a finding is not an
ownership attestation.

## Stored requirements and owner signing

Requirements come from `SecTrustedApplicationCopyRequirement`, never from the
present binary at a stale path. That SPI and
`SecTrustedApplicationCreateFromRequirement` are resolved at startup. Missing
symbols fail loudly before any query. A failed or missing stored requirement
is `unverified` and `requirement_unknown`; bind and verify refuse it. An owner
decision for a kept app cannot override unreadable stored trust.

The conservative classifier accepts understood positive conjunctions;
unfamiliar syntax, including disjunctions, requires review. Owner decision 75
requires a specific certificate pin: `certificate leaf = H"<sha1>"`,
`certificate root = H"<sha1>"`, or the equivalent `anchor = H"<sha1>"`.
Apple's [requirement language](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
defines anchor as the root certificate; macOS serializes its hash pin as
`certificate root`. Team-OU requirements without a certificate pin
are classified `team_ou_forgeable`, flagged by inventory and refused by bind
and verify, with or without an identifier and with quoted or bare Team values.
On this host, every developer key of the team signs silently. Any process
able to use one can choose the owner's identifier and satisfy the same
Apple-anchor/Team-OU DR. The OU identifies the whole team, not the dedicated
owner certificate, so adding an identifier does not prevent this forgery.
Leaf/root hash pins select a specific certificate instead. These checks do
not change signing-key custody; decision 75's separate signer-user isolation
remains the keeper's responsibility. An Apple anchor or team ID alone is
insufficient. Paired tests cover team-only refusal/inventory flags and accepted
leaf/root/anchor pins, including native requirement serialization.

The signature must validate, the owner must not be a generic reader, hardened
runtime must be present, and none of these entitlements may be present (even
with a false value):

- `com.apple.security.get-task-allow` (also bare `get-task-allow`)
- `com.apple.security.cs.allow-dyld-environment-variables`
- `com.apple.security.cs.disable-library-validation`
- `com.apple.security.cs.allow-unsigned-executable-memory`

Apple-internal exceptions use a **closed identifier allowlist** in
`internal/toolsecret/model.go`. **Approved identifiers: none.** No Apple app
is retained implicitly. Adding an identifier requires reviewed source and
documentation changes; an approved entry would still need its stored Apple
anchor and must not be a generic reader. `/usr/bin/security`, osascript,
shells and Python remain generic readers regardless of their anchor or a
misleading recorded path.

SPI presence and metadata behavior were verified on **macOS 26.5.1, build
25F80** (`sw_vers`). Repeat the disposable-keychain lane after OS updates.

## Binding and verification

```sh
mac-tool-secret bind --keychain /absolute/test.keychain-db --service SERVICE --account ACCOUNT --owner /absolute/owner --dry-run --json
mac-tool-secret bind --service SERVICE --account ACCOUNT --owner /absolute/owner --owner-sitting
mac-tool-secret bind --service SERVICE --account ACCOUNT --owner /absolute/owner --owner-sitting --keep /absolute/exception --owner-decision decision:REFERENCE
mac-tool-secret verify --service SERVICE --account ACCOUNT --owner /absolute/owner --json
```

Ship the signed hardened owner reader and its status-only self-check, switch
all consumers to it at their keeper's safe point, and only then rebind a real
item. The metadata tool never runs that positive self-check. Retained rollback
items trusting generic readers still need separate owner-approved retirement.

Bind requires `--owner-sitting` and TTYs on stdin and stdout. The flag is
refused whenever `TMUX` or `STY` is set, including an empty value. Passwords go
only into system dialogs; there is no password argument, file, stdin or
worker-protocol path. Before authorization, bind prints the exact item,
owner DR, proposed partition list and exceptions with control characters
escaped. All queries disable UI globally and use `kSecUseAuthenticationUIFail`.
Native calls run in killable subprocesses: queries have a 10-second deadline,
and one attended mutation has a 60-second deadline. No refused authorization
is retried. A mutation timeout has an unknown outcome; inventory before any
further action.

Binding removes plaintext-release authorizations from every existing entry,
preserving unrelated explicit authorizations. A wildcard `any` entry is
removed entirely because it cannot express "any except plaintext". New
entries grant decrypt, export_clear and export_wrapped only to the owner and
explicitly approved keeps. Item attributes and value stay in place.
Other explicit writer grants are preserved; strict verify can therefore still
fail on `foreign_writer` after bind. Removing wildcard `any` entries removes
their writer authority too. Bind does not claim to repair foreign writers.

Each `--keep` application must pass the same owner checks, including a
specific certificate pin, and its current DR must match its stored DR.
Otherwise bind refuses unless `--owner-decision REF` explicitly authorizes
the exception. The audit records the reference, kept paths and available
signing metadata. This does not relax primary-owner checks or permit
unverified stored requirements. A strict verify can still fail on extra kept
owners or unsafe exceptions; it has no exception flag.

The partition list becomes exactly `teamid:TEAM` for recognized Apple
development/Developer ID certificate families (the certificate OU is checked),
or securityd's `cdhash:HASH` fallback for other signed owners. Neither
`apple:` nor `apple-tool:` remains. Option-B cdhash partitions need rebinding
after each rebuild even when the certificate-pinned DR is stable.

The modified ACL and partition list are submitted through one
`SecKeychainItemSetAccess` call. This uses the native system authorization
path; where macOS offers Always Allow, the owner chooses it in that dialog.
There is no `security set-*-partition-list` subprocess or password bypass.
The real dialog is unexercised. Snapshot and signature rechecks precede
mutation, but cannot make external concurrent ACL edits atomic. Dry-run
prints a metadata-only plan, without mutation, UI or audit writes.

## Append-only hash-chained audit

The log is `~/Library/Application Support/mac-infra/tool-secret/audit.jsonl`,
with a separate `audit.jsonl.head` checkpoint. Both are owner-owned regular
`0600` files. Links, permissive state, multiple hardlinks and concurrent binds
are refused. The tool opens the log with `O_APPEND` and never truncates or
rewrites it. Every record includes time, actor UID, before/after metadata,
kept applications, owner decision, outcome, sequence, previous-record hash
and its own SHA-256. It never has an item value/data/password field.

Intent is fsynced before mutation; the outcome is fsynced afterwards, with an
atomic durable checkpoint update after each append. A crash between log and
checkpoint updates fails closed and needs reviewed recovery; the tool never
silently repairs or migrates old/unverifiable audit files.

```sh
mac-tool-secret verify-audit --json
mac-tool-secret verify-audit --audit-log /absolute/audit.jsonl --expected-head PREVIOUSLY_TRUSTED_SHA256 --json
```

Verification detects changed records, reordering, truncation, partial writes
and a fully rehashed log that disagrees with the checkpoint. Pinning a trusted
head outside this directory also detects replacement of both local files.
The hash chain is not an authenticated signature: a same-user writer who can
rewrite both files and the external pin can forge a new history. `O_APPEND`
describes this tool's writes; it is not a filesystem immutable flag.

## Separate three-outcome probe and tests

```sh
mac-tool-secret-probe --keychain /absolute/test.keychain-db --service SERVICE --account ACCOUNT
```

The separately signed probe never examines or outputs returned bytes. It
checks keychain lock state before and after its bounded UI-disabled read:

- `refused`: only errSecInteractionNotAllowed or errSecAuthFailed on the read;
  exit 0, a passing negative check.
- `allowed`: exit 1, a failing negative check.
- `inconclusive`: locked, missing, timeout or any other error; exit 1.

In JSON, `ok` is true only for refused; `result` always names the outcome.
Failures also carry the common `error:{code,message,hint}` envelope. The
metadata commands use that envelope as well; a full inventory writes it only
to its local file. Metadata CLI exits: 0 success, 1 operational, 2 usage,
3 policy refusal. The probe uses exit 2 for usage errors.

Default tests use fake backends and local audit/export files, with no keychain
I/O. `MAC_TOOL_SECRET_KEYCHAIN_TESTS=1` enables disposable keychains under
`t.TempDir`, random stdin-only test passwords, UI-disabled bounded calls, and
search-list capture/restoration/assertion. Native fixtures cover security-style,
ad-hoc, identifier, export, wildcard and paired writer grants; the probe's passing refusal
and failing allowed/missing/locked cases; and stale-path classification.
The security-style fixture uses `SecAccessCreate` trusting `/usr/bin/security`,
without launching a generic reader with an item password.

On **macOS 26.5.1**, `SecKeychainItemSetAccess` raises a SecurityAgent
dialog on the owner's screen even after
`SecKeychainSetUserInteractionAllowed(false)`. That dialog can outlive the
calling process, and while it is open, securityd blocks every other keychain
client on the host. On 2026-10-29 at 11:30Z a test that attempted this on a
disposable keychain left such a dialog for about 30 minutes, until the owner
dismissed it. A subprocess deadline cannot contain it. Therefore:

- **No test calls SecKeychainItemSetAccess**, and no test exercises `bind`.
  The former single-attempt test was removed, not bounded; it must not be
  restored.
- The only call is in the attended region of `native_darwin.m`. The native
  layer refuses with errSecInteractionNotAllowed unless UI is allowed and
  fds 3 and 4 are terminals. The worker refuses any unattended `apply`
  before native dispatch. `TestSetAccessOnlyInAttendedRegion` and
  `TestWorkerRefusesUnattendedApplyBeforeDispatch` pin both properties.
- The opt-in tests cover inventory, writers, requirement pins and the
  probe's three outcomes, with UI disabled in every fixture binary.

Bind remains gated behind `--owner-sitting`, both TTYs and no TMUX/STY. Its
real dialog and successful authorization/mutation are **not exercised end to
end**. Partition changes needing UI, full certificate-pinned bind/rebuilt-owner
acceptance, and sysadmin env/argv/DYLD checks remain unexercised lanes requiring
an admitted signing fixture. Weak experimental identities never pass production
owner validation. Native tests do not retry the blocked operation or search
for a successful variant.

Apple source references: [trusted-application SPI declarations](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_keychain/lib/SecTrustedApplicationPriv.h)
and [securityd partition assignment](https://github.com/apple-oss-distributions/Security/blob/main/securityd/src/clientid.cpp).
