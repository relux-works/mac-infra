# Claude policy metadata journal

Owner decision, 2026-11-04: build the metadata-only journal. Reading policy
contents, hashing them, or recording a diff requires a separate decision.

`mac-policy-journal` observes exactly `remote-settings.json` and
`policy-limits.json`. It records observation time, event kind, home path,
basename, presence/availability, byte size, modification time and inode. It does
not invoke content-read operations on these files. macOS vnode descriptors use `O_EVTONLY`
and `O_NOFOLLOW`; the metadata observer interface exposes only `Lstat` and
directory enumeration. File symlinks and special nodes are unsupported.

Automatic discovery covers `USER/.claude` and
`USER/.curator/environments/*/claude_code`. It enumerates only the environments
directory and does not traverse projects, sessions or native configuration.
For other `CLAUDE_CONFIG_DIR` locations, supply each absolute home with `--home`.
Directory symlinks, including ancestor components, are not followed; declare
the canonical home instead. Coverage is therefore the declared topology, not
a claim to discover arbitrary paths used by unknown processes.

Optional default homes that do not exist are skipped silently. An explicitly
declared `--home` that does not exist below a valid parent is recorded as
`home_absent`, once per absence, and its parent directory is watched so that a
later creation is baselined. A declared home whose path is a regular file, a
symlink or below an unusable parent is a `coverage_gap`.

## Output admission

The journal basename must be lowercase ASCII ending in `.jsonl` or `.log`
(`events.jsonl` and `service.log` are the forms the service uses). Under case
and Unicode-normalization folding no such name equals a monitored `.json`
policy file, so an alias such as `REMOTE-SETTINGS.JSON` is refused before any
open, including when the policy file does not exist yet. The journal directory
must not be the same filesystem object as a monitored home, whatever path
reaches it; the observer rechecks this on every discovery and stops instead of
writing there. After opening, the journal must not be the same object as any
monitored policy file. Symlinked components, hardlinked files, other owners and
group/world permissions are refused as before.

## Run and installation

Build/install from a clean standalone checkout of the accepted commit:

```sh
./scripts/setup.sh --only mac-policy-journal
mac-policy-journal help
mac-policy-journal enable
mac-policy-journal status
```

Enable writes only the new current-user LaunchAgent
`~/Library/LaunchAgents/works.relux.mac-infra-claude-policy-journal.plist` and
private state under
`~/Library/Application Support/mac-infra/claude-policy-journal/`. It starts
that job through `launchctl bootstrap gui/UID`. The job runs the exact installed
executable, with no shell, profile composition or native session launch.
`events.jsonl` is the journal; `service.log` contains sanitized operational
errors. Both files must be owned, private regular files with a single link;
the state directory must be private. An exclusive nonblocking journal lock
rejects a second writer. Existing plist files are retained and refused.

To include a separately located home, pass `enable --home /canonical/home`.
To stop this observer without deleting records:

```sh
mac-policy-journal disable
```

The plist remains. To resume that existing job, use
`launchctl bootstrap gui/$(id -u) "$HOME/Library/LaunchAgents/works.relux.mac-infra-claude-policy-journal.plist"`.
No policy permissions, immutable flags, credentials or native runtimes change.

For a finite foreground observation, first create an owned private output
directory and use its canonical absolute path:

```sh
mkdir -m 700 .temp/policy-journal
mac-policy-journal run --user-root "$HOME" \
  --journal "$(pwd -P)/.temp/policy-journal/events.jsonl" \
  --rescan 30s --duration 2m
```

## Interpretation and limits

Every start records `observer_start` and a baseline for each supported file,
including absent files. Metadata deltas become `metadata_change`. A direct
file notification is retained as `file_event` even when the sampled fields
are unchanged. Atomic replacement is detected by inode and the watch is
rearmed. Directory notifications and the explicit 30-second rescan discover
new homes/files and removal. Unavailable/unsupported inputs and watch failures
are visible in records; `coverage_gap` means some discovery/watch coverage
could not be established. The observer continues the remaining admitted paths.

Vnode events may coalesce. Changes during startup/rearming, interruption or
between observation and sampling can be missed; arbitrary locations not
declared above are unobserved. A readable file is needed to open its event-only
descriptor. `O_EVTONLY` is not OS read isolation: a synthetic control on this
macOS could read through such a descriptor. The implementation does not invoke
that operation. Its closed input-operation vocabulary is checked at source;
this is a review tripwire, not enforcement against altered code. A clean stop records
`observer_stop`; abrupt death may omit it. Append writes are synced on clean
exit, not individually guaranteed against power loss. Journal records are not
one-to-one write counts, a lossless audit, or proof that policy was received or
applied in memory. Size growth alone cannot establish policy semantics.

This tool observes. The separate OS write-protection fixture does not deploy
protection into live homes, and the journal changes no write policy.

## Verification

```sh
GOWORK=off GOTOOLCHAIN=local go test ./internal/policyjournal ./cmd/mac-policy-journal
```

Tests use synthetic homes only. They cover metadata transitions, exact output
fields with sentinel content excluded, bounded discovery, aliases refused,
journal name forms, output separation from policy files and homes (exact names,
case aliases of present and absent policies, symlink and hardlink), declared
homes that are absent, present, replaced by a file or a symlink, and their
creation and removal,
real vnode notifications and replacement, unreadable-file coverage gaps,
the actual event-descriptor read-isolation limit, a source-operation guard
with violating read-call controls, private
single-writer admission, finite observation and generated LaunchAgent XML.
They do not start a live LaunchAgent or mutate an existing Claude home.
