# netfilter

A maintained mac-infra security tool for per-app traffic analysis: an
`NEFilterDataProvider` system extension that attributes every socket flow to
its program and logs it. It is observe-only by default (owner decision
2026-10-23). Design, signing and risks are in [DESIGN.md](DESIGN.md); the
decision specs are on the board (STORY-261023-qbc86k). Wiring into the
firewallwatch classifier and a narrow, journaled kill path are in progress.

## Tests

The identity resolver (`Shared/`) has a SwiftPM harness. Run it outside the extension:

```sh
swift test
```

## Build

Unsigned (compile check only; the extension cannot be activated while SIP is on):

```bash
cd apps/netfilter
xcodegen generate
xcodebuild -project NetFilter.xcodeproj -scheme NetFilter \
  -configuration Debug -derivedDataPath <dir> CODE_SIGNING_ALLOWED=NO build
```

Signed (paid team with the Network Extension capability, development profiles
for both bundle IDs):

```bash
xcodegen generate
xcodebuild -project NetFilter.xcodeproj -scheme NetFilter \
  -configuration Debug -derivedDataPath <dir> \
  DEVELOPMENT_TEAM=<TEAM_ID> -allowProvisioningUpdates build
```

`DEVELOPMENT_TEAM` is never hard-coded; pass it on the command line or via the
environment.

## Owner steps (never run unattended)

1. Copy the signed app to `/Applications`.
2. Run `/Applications/NetFilter.app/Contents/MacOS/NetFilter activate`,
   then approve it in System Settings > General > Login Items & Extensions >
   Network Extensions.
3. Run `... enable`, then answer "Allow" on the "would like to filter network
   content" prompt (admin password).
4. Run `./tail-flows.sh ~/netfilter-flows.jsonl` while browsing with multi-tun up.
5. Undo: `... disable`, `... remove`, `... deactivate`, then delete the app.

Upgrading from the prototype app (`/Applications/NetFilterProto.app`, same
bundle IDs): install `NetFilter.app`, run its `activate` and `status`, and
only then delete `NetFilterProto.app`. Deleting the app that owns the active
extension uninstalls the extension.

App commands: `activate`, `deactivate`, `enable`, `disable`, `remove`, `status`.

## Output

The extension logs one JSON object per flow to the unified log (subsystem
`works.relux.mac-infra.netfilter`, category `flow`). `tail-flows.sh OUT.jsonl`
appends them to `OUT.jsonl`, one line per flow, no sudo needed. Build artifacts
go to the `-derivedDataPath` directory; the generated `*.xcodeproj` is not
committed.
