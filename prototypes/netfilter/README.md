# netfilter prototype

Prototype, not a release: an observe-only per-app outbound flow logger built on
an `NEFilterDataProvider` system extension. Design, signing and risks are in
[DESIGN.md](DESIGN.md).

## Build

Unsigned (compile check only; the extension cannot be activated while SIP is on):

```bash
cd prototypes/netfilter
xcodegen generate
xcodebuild -project NetFilterProto.xcodeproj -scheme NetFilterProto \
  -configuration Debug -derivedDataPath <dir> CODE_SIGNING_ALLOWED=NO build
```

Signed (paid team with the Network Extension capability, development profiles
for both bundle IDs):

```bash
xcodegen generate
xcodebuild -project NetFilterProto.xcodeproj -scheme NetFilterProto \
  -configuration Debug -derivedDataPath <dir> \
  DEVELOPMENT_TEAM=<TEAM_ID> -allowProvisioningUpdates build
```

`DEVELOPMENT_TEAM` is never hard-coded; pass it on the command line or via the
environment.

## Owner steps (never run unattended)

1. Copy the signed app to `/Applications`.
2. Run `/Applications/NetFilterProto.app/Contents/MacOS/NetFilterProto activate`,
   then approve it in System Settings > General > Login Items & Extensions >
   Network Extensions.
3. Run `... enable`, then answer "Allow" on the "would like to filter network
   content" prompt (admin password).
4. Run `./tail-flows.sh ~/netfilter-flows.jsonl` while browsing with multi-tun up.
5. Undo: `... disable`, `... remove`, `... deactivate`, then delete the app.

App commands: `activate`, `deactivate`, `enable`, `disable`, `remove`, `status`.

## Output

The extension logs one JSON object per flow to the unified log (subsystem
`works.relux.mac-infra.netfilter`, category `flow`). `tail-flows.sh OUT.jsonl`
appends them to `OUT.jsonl`, one line per flow, no sudo needed. Build artifacts
go to the `-derivedDataPath` directory; the generated `*.xcodeproj` is not
committed.
