# Firewall management (`mac-firewall`)

`mac-firewall` manages the macOS application firewall from a declarative
config. Every query and change runs inside the installed `mac-infra-core`
root helper, so the operator needs sudo once (helper install) and never per
change. The helper re-validates every request; the CLI's own checks are a
convenience.

## Commands

| Command | Effect |
| --- | --- |
| `mac-firewall status [--json]` | Firewall state, app exceptions, allowlisted services, TCP listeners (root view, so every process; UDP is not inspected). Listener entries carry pid, uid and bind only, never process names or argv. |
| `mac-firewall init-config [--config PATH]` | Writes a `0600` config seeded from the current state with `apps.mode: listed`, so applying it unchanged is a no-op. Never overwrites. Entries that socketfilterfw reports by bundle id cannot be listed by path and are printed instead. |
| `mac-firewall plan [--config PATH] [--json]` | Dry run: prints each step marked `tightens` or `LOOSENS`. Runs no mutating command. |
| `mac-firewall apply [--config PATH] [--apply] [--json]` | Without `--apply`, the same as `plan`. With it, applies (see below). |

Default config path: `~/.config/mac-infra/firewall.json`. The CLI refuses a
config that is not a regular file owned by the caller, or that is group- or
world-writable.

Exit codes: 0 success, 1 refused / failed / rolled back, 2 usage.

## Config (`mac-infra.firewall/v1`)

```json
{
  "schema": "mac-infra.firewall/v1",
  "stealth": true,
  "block_all": false,
  "allow_signed_builtin": true,
  "allow_signed_downloaded": true,
  "apps": {
    "mode": "listed",
    "allow": ["/Applications/Example.app"],
    "block": ["/usr/local/bin/example-daemon"]
  },
  "services": { "disable": ["apache"] }
}
```

- Unknown fields are rejected. There is deliberately no field for the global
  firewall state: the tool turns it on and keeps it on, and cannot turn it off.
- An omitted toggle is unmanaged and left as it is.
- `apps.mode`:
  - `listed` manages only the listed paths.
  - `exact` also removes path entries that are not listed. Bundle-id entries
    are reported as `unmanaged` and left untouched.
- App paths must be clean absolute paths to an existing file or bundle, not
  symlinks, without leading or trailing whitespace (socketfilterfw pads its
  listing, so such names could not be read back unambiguously). A config path also matches an entry that socketfilterfw lists
  under the bundle's `CFBundleIdentifier`.
- `services.disable` accepts only names from the code-reviewed allowlist.
  v1 has `apache` = `system/org.apache.httpd`. Disabling means
  `launchctl disable` (persistent) plus `launchctl bootout` (stop now).
  Removing a name from the list does not re-enable the service.

## Trust model

The helper serves only the installed client UID (and root), so any process
running as that user can request a change. That is the point: the operator
(the sysadmin keeper) manages the firewall without sudo. Guardrails:

- Tightening is always allowed: firewall on, stealth on, block-all on, block
  or remove an allowed app, disable an allowlisted service.
- Allowing an app (new allowed entry or unblock) requires
  `codesign --verify -R="anchor apple generic"` to pass in the helper.
  Ad-hoc and unsigned code are refused. The signing identifier and team id go
  into the plan and the audit.
  - `--strict` is not used: it also rejects validly signed apps over Finder
    metadata (for example Google Chrome).
  - The signature check guards against operator mistakes (allowing unsigned
    or ad-hoc code by accident). It is not a boundary against a malicious
    process running as the client UID: that process may replace the bundle
    between the check and `socketfilterfw --add` (the helper re-verifies after
    apply, but a swap-and-restore passes both checks), and it may loosen the
    global toggles anyway.
- Existing exceptions that stay as they are need no signature (for example an
  unsigned app that is already allowed).
- Global loosening toggles (stealth off, block-all off, signed auto-allow on)
  and removing a blocked entry are allowed. They are marked `LOOSENS` and
  audited.
- Turning the firewall off is impossible. The helper's exec allowlist has no
  `--setglobalstate off`, so not even a planner bug can send it.
- The helper executes only fixed argv from a vocabulary of `socketfilterfw`,
  `launchctl` (allowlisted labels only), `codesign`, `plutil` and `lsof`. It
  never runs a shell.
- Requests are bounded: 256 KiB, a 10 s read deadline, a 10 s write deadline,
  16 concurrent connections (further ones are closed unread). One firewall
  operation runs at a time; a request that cannot start within 30 s is
  refused as busy.
- JSON is decoded by Go's `encoding/json` with unknown fields refused. It is
  not a canonical-JSON validator: a duplicate key is applied again over the
  earlier value (a repeated object merges into the earlier one, so a second
  `apps` object with only `mode` keeps the earlier lists), field names match
  case-insensitively, and the daemon serves the first JSON object on a
  connection without checking for trailing data (`ParseConfig` does refuse
  trailing data in a config file). None of this lets the client UID request
  anything it could not request directly, and the CLI always sends its own
  re-encoded config, so the plan it shows is the config it applies.

## Apply semantics

1. Observe the full state. Unrecognized output from any tool refuses the
   apply.
2. Plan and validate everything, including signatures. Any error refuses
   before the first mutation.
3. Write an `apply_intent` audit record. If the audit cannot be written, the
   apply is refused with no change (fail closed).
4. Run the steps. Then read back and re-plan; the result must be empty.
5. If any step or the readback fails, every started step is undone in reverse
   (best effort, continuing past failing undos) and the state is read back.
   Rollback runs on its own two-minute budget, so an apply that ran out of
   time can still undo its changes. Undoing a service stop enables the
   service, loads it, and restores its disabled override, because launchd
   will not load a disabled service.
   - `rolled_back`: equal to the pre-apply state, except that the firewall
     stays on if this apply turned it on.
   - `rollback_failed`: an incident; the report carries the drift.
   - socketfilterfw has no transactions, so this is compensating rollback,
     not atomicity.
6. Write an `apply_result` audit record. After `applied` or `no_change`, the
   firewall is marked managed.

A second apply of the same config plans zero steps.

## Keep-on enforcement and audit

Once a firewall is marked managed, the helper checks every five minutes and
turns it back on if anything turned it off. This is tightening only, it is
audited as `enforce`, and it does nothing before the first successful apply.
Unlike apply, it is not gated on the audit: a full or broken audit store must
not keep the firewall off. Audit failures go to the daemon's stderr log.

The audit trail and marker live in
`/Library/PrivilegedHelperTools/works.relux.mac-infra/firewall/`:

- `audit.jsonl` (`root`, `0644`, JSON lines)
- `managed.json`

Both are opened relative to trust-checked descriptors: no symlinks, no group
or world write, single hard link, safe ACLs.

## Install (one sudo)

```bash
./scripts/setup.sh                                   # user only: builds and links tools
mac-infra-core install-digest                        # no privilege: path, version, sha256
mac-infra-core install --expect-sha256 <sha256>      # prints the digest, one sudo prompt
mac-infra-core status
mac-firewall status
```

`install` refuses before sudo if the executable differs from the reviewed
digest. It also refuses stray arguments (they would end flag parsing before a
later `--expect-sha256`) and an empty or malformed digest.

## Limits

- UDP listeners are not inspected.
- The keep-on check runs every five minutes, not on events.
- The audit log is not rotated.
- Entries that socketfilterfw reports by bundle id cannot be removed in
  exact mode.
- No packet-filter (`pf`) management.
