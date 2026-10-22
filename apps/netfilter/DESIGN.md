# netfilter: design note

Status: **maintained tool** (owner decision 2026-10-23: "доделываем его до
ума"), observe-only by default. It started on 2026-10-22 as a per-app outbound
visibility prototype ("own Little Snitch"). The decision specs (owner quotes,
architecture, kill path, journal, digest contract) are board resources of
STORY-261023-qbc86k; this note describes what is built.

## Shape

| Part | What it is |
| --- | --- |
| `NetFilter.app` | Containing app. It has no UI and runs from a terminal: `Contents/MacOS/NetFilter <command>`. It must run from `/Applications`. |
| `works.relux.mac-infra.netfilter.extension.systemextension` | Embedded at `Contents/Library/SystemExtensions/`. It is an `NEFilterDataProvider` subclass. |
| `tail-flows.sh OUT.jsonl` | Turns the extension's unified-log lines into one JSONL file, without sudo. |
| `project.yml` | xcodegen spec. The generated `.xcodeproj` is not committed. |

App commands: `activate` and `deactivate` (`OSSystemExtensionRequest`),
`enable` and `disable` (the `NEFilterManager` configuration and its
`isEnabled`), `remove` (removes the configuration), `status`. Each command
does one thing, prints a single result line and exits non-zero on failure.

## Filter behaviour

- `NEFilterProviderConfiguration`: `filterSockets = true`,
  `filterPackets = false`, `filterBrowsers = false`. There is no packet
  tunnel, no transparent proxy and no DNS proxy.
- `startFilter`: apply `NEFilterSettings(rules: [], defaultAction:
  .filterData)`, so every new non-loopback flow reaches `handleNewFlow`.
- `handleNewFlow`: log the flow, then return `.allow()` at once. There is
  no `filterDataVerdict` follow-up, so no data inspection and no added
  latency beyond one log call.
- Never `.drop()`. No code path can block a flow.

## Event (one JSON object per flow)

The extension emits each event with `Logger(subsystem:
"works.relux.mac-infra.netfilter", category: "flow")` and `.public` privacy.
`tail-flows.sh` runs `log stream --style ndjson --level info` with that predicate and
writes each event's message as one line.

| Field | Source |
| --- | --- |
| `ts` | event time, RFC 3339 |
| `flow_id` | `flow.identifier` |
| `direction` | `outbound` or `inbound` (`flow.direction`) |
| `proto` | `tcp` or `udp` from `socketProtocol`, else the number |
| `remote_hostname` | `flow.remoteHostname`; null when the app connected by IP |
| `remote_host`, `remote_port` | `remoteFlowEndpoint` (macOS 15+) |
| `local_port` | `localFlowEndpoint` |
| `app_signing_id`, `app_team_id`, `app_path`, `app_pid` | from `sourceAppAuditToken`: `SecCodeCopyGuestWithAttributes` with the audit token, then `SecCodeCopySigningInformation` and `SecCodeCopyPath`; pid via `audit_token_to_pid` |
| `app_signing_status` | `signed`, `adhoc` (no certificate, e.g. Homebrew builds), `unsigned`, `unverified` (path known, signature unreadable) or `unresolved` (no path) |
| `app_identity_source` | `audit_token` (Security framework, which checks the pid version), `pid_path` (fallback, see below) or `none` |
| `via_process_path` | only when `sourceProcessAuditToken` differs from the app token (a system process acting for the app) |

Identity fallback (`Shared/AppIdentity.swift`): when the audit-token lookup
fails, the extension reads the token's pid with `proc_pidpath` and classifies
the file's signature. A pid can be reused, so the fallback reads the process
start time via `sysctl(KERN_PROC_PID)` before and after the path lookup. It
reports `unresolved` with no path when the process started after the flow was
observed, when the two start times differ, or when the pid is gone. It never
reports a wrong path.

Run 01 showed that in the sandboxed extension the lookup failed for code
outside system paths and `/Applications` (Homebrew sing-box, the Codex CLI),
while the same calls succeed unsandboxed. The extension therefore carries a
read-only sandbox file exception for `/`, so it can read signatures.

Why `/` and not a list of directories: the program behind a flow can live
anywhere: Homebrew prefixes, `~/.local/bin`, npm `node_modules`, SDK
folders, build outputs in project directories. Run 02 attributed flows
from all of these. A narrower list would turn every new location back into
an unattributed flow. The exception is limited as follows:

- It is read-only (`files.absolute-path.read-only`). The extension gets no
  file write, network client/server or other sandbox right beyond its
  defaults.
- Only the Security framework reads files through it, to validate the code
  signature of the flow's program. The extension never opens files itself
  and writes nothing but unified-log lines.
- It is a development-signing exception. A Developer ID
  or App Store build would have to revisit it, for example by moving the
  signature lookup into a separate helper process.

`remote_hostname` is preferred over the IP. Under multi-tun's fake-ip DNS,
`remote_host` is often a 198.18.0.0/15 placeholder. The real name is only
there when the app connected by name through Network.framework or CFNetwork.

Writing JSONL from the extension itself was rejected. A network system
extension runs as root inside an app sandbox, so its file would sit in root's
container and need sudo to read. The unified log is readable by the admin
user and needs no extra entitlement.

## Kill path (owner decision D7; spec-kill-path.md)

Observe-only stays the default. The kill path is narrow, journaled at the
CLI, and off until the owner installs the protect-list.

- **Protect-list**: `/Library/Application Support/works.relux.mac-infra.netfilter/protect.json`,
  root-owned. Changing it needs sudo, i.e. the owner. Schema
  `mac-infra.netfilter-protect/v1`; each entry has one matcher (`app_path`,
  `app_path_prefix`, `signing_id` or `host_suffix`, matched on a label
  boundary) and a `reason`. The extension rereads it at start and before
  every kill or block. **Missing or invalid file = enforcement off**: every
  flow is allowed at once (as in 0.2), and kill and block are refused.
- **New flows** (`Shared/Enforcement.swift`, `Engine`):
  - protected flows are allowed at once, never killable and never slowed;
  - a flow that matches an active block is dropped;
  - every other flow stays under data filtering. A callback comes after about
    1 MiB per direction (`passWindow`), no payload is kept, and the flow sits
    in a bounded table of 4096 entries (oldest evicted). A later kill can
    then reach it with `update(flow, .drop())`, which only works on flows
    still under data filtering.
- **Control**: an XPC service on `NEMachServiceName`, with the code-signing
  requirement "same team and identifier `works.relux.mac-infra.netfilter`".
  Requests:
  - `kill` (flow id, or app/host/port tuple);
  - `block` (tuple plus duration, at most 24 h, in memory only: an extension
    restart clears every block);
  - `unblock`;
  - `list`.
  An actor is required. Drops run outside the state lock.
- **Audit**: every applied or refused action goes to the unified log
  (category `action`) for the watcher to reconcile with the journal.
- **Fail-safe**: no protect-list, no control service, or no request means
  nothing is blocked.



- Development signing: Apple Development certificate plus development
  provisioning profiles for both bundle IDs, in a paid team the owner names.
  Personal teams cannot get the Network Extension capability.
- Bundle IDs: `works.relux.mac-infra.netfilter` (app),
  `works.relux.mac-infra.netfilter.extension` (extension).
- App entitlements: `com.apple.developer.networking.networkextension =
  [content-filter-provider]`, `com.apple.developer.system-extension.install =
  true`.
- Extension entitlements: the same NE entitlement,
  `com.apple.security.app-sandbox = true`,
  `com.apple.security.temporary-exception.files.absolute-path.read-only = [/]`
  (to read other programs' code signatures), and
  `com.apple.security.application-groups = [$(TeamIdentifierPrefix)works.relux.mac-infra.netfilter]`.
- Extension `Info.plist` `NetworkExtension` dictionary:
  `NEMachServiceName = $(TeamIdentifierPrefix)works.relux.mac-infra.netfilter.extension`,
  `NEProviderClasses = { com.apple.networkextension.filter-data =
  $(PRODUCT_MODULE_NAME).FilterDataProvider }`.
- Both `Info.plist` files carry `NSSystemExtensionUsageDescription`. For the
  network_extension category it is required: without it the first owner
  activation failed with OSSystemExtensionErrorDomain 9.
- Development profiles use `content-filter-provider`. A Developer ID build
  would need `content-filter-provider-systemextension`, which is out of
  scope.
- Without a team, the build uses `CODE_SIGNING_ALLOWED=NO`. It proves that
  everything compiles; activation is impossible while SIP is on.

## Owner steps (prepared, never triggered unattended)

1. Copy the signed app to `/Applications`.
2. Run `/Applications/NetFilter.app/Contents/MacOS/NetFilter activate`,
   then approve it in System Settings > General > Login Items & Extensions >
   Network Extensions.
3. Run `… enable`, then answer "Allow" on the "would like to filter network
   content" prompt (admin password).
4. Run `tail-flows.sh ~/netfilter-flows.jsonl` while browsing with multi-tun
   up.
5. Undo: `… disable`, `… remove`, `… deactivate`, then delete the app.

## Risks

- **Coexistence.** Cisco AnyConnect's socket filter is already an active
  content filter, and Tailscale's network extension is active too. A second
  content filter is expected to coexist; the manual run checks this.
- **multi-tun.** The filter sees socket flows before routing, so it neither
  touches nor depends on the sing-box utun. With fake-ip, IPs are
  placeholders and hostnames may be missing (see the event table).
- **Kill-switch.** An allow-all filter adds no drops, but a hung extension
  delays new flows until macOS gives up on it. The manual run checks
  fail-open by deactivating during traffic.
- **Privacy.** Hostnames and app paths go to the unified log as public
  strings, on the owner's own Mac. Hostnames are kept: they are the whole
  point of the probe.
