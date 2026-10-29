# Firewall management (`mac-firewall`)

`mac-firewall` manages the macOS application firewall from a declarative
config. Management queries and changes run inside the installed `mac-infra-core`
root helper, so the operator needs sudo once (helper install) and never per
change. The helper re-validates every request; the CLI's own checks are a
convenience.

## Commands

| Command | Effect |
| --- | --- |
| `mac-firewall status [--json]` | Firewall state, app exceptions, allowlisted services, TCP listeners (root view, so every process; UDP is not inspected). Listener entries carry pid, uid and bind only, never process names or argv. If the listener listing fails, the state is still printed, `--json` carries `listener_error`, and the exit code is 1. |
| `mac-firewall init-config [--config PATH]` | Writes a `0600` config seeded from the current state with `apps.mode: listed`, so applying it unchanged is a no-op. Never overwrites. Entries that socketfilterfw reports by bundle id cannot be listed by path and are printed instead. Needs only the firewall state: a failed listener listing does not block it. |
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

## Watch (shadow mode)

`watch` is a separate, unprivileged observer. It never blocks traffic, changes
firewall settings, or calls `mac-infra-core`. Every label is a proposal with
`mode: "shadow"`; only `new-events.flag` notifies the keeper. No network
notification or a2a message is sent. Embeddings use a watcher-owned foreground
llama-server child through `<state_dir>/llm.sock` only; no TCP listener is
created. The HTTP transport dials only that UNIX socket, refuses proxies and
redirects, and checks Darwin `LOCAL_PEERPID` against the child PID before sending
requests. Child exit permanently invalidates that binding; another listener is
never adopted. A stale socket is removed only when it is caller-owned and a
connection is refused; live listeners and non-socket objects refuse startup.

Before exec, the model is opened with `O_RDONLY|O_NOFOLLOW|O_NONBLOCK` and fstat
must show a regular caller/root-owned file, without group/world writes, within
`max_model_bytes`. Chunked SHA-256 verification checks cancellation and the
overall startup deadline, which starts before open. The same open description
is inherited through `ExtraFiles` as fd 3 and loaded with `-m /dev/fd/3`.
Path replacement after verification cannot select a different inode. Concurrent
in-place modification by a trusted owner after verification is outside this
pinning guarantee; keep model contents unchanged while running. There is no
pathname fallback.

```sh
mac-firewall watch run --config /ABSOLUTE/firewall-watch.json
mac-firewall watch digest --config /ABSOLUTE/firewall-watch.json --since 24h
mac-firewall watch digest --config /ABSOLUTE/firewall-watch.json --since 24h --json
mac-firewall watch digest --config /ABSOLUTE/firewall-watch.json --since 24h --json --split
mac-firewall watch status --config /ABSOLUTE/firewall-watch.json --json
mac-firewall watch classify --config /ABSOLUTE/firewall-watch.json --fixtures /ABSOLUTE/fixtures-v2-heldout.jsonl --json
```

`run` stays in the foreground. SIGINT/SIGTERM stop collection and reap its
llama-server child. Exit codes are 0 success, 1 refused/failed, 2 bad usage.
`status` reports last persisted backend health with its observation time, not
a live health probe; a stale timestamp may mean the watcher has stopped.
The persisted health also reports `line_queue_high_water` (`alf` and
`netfilter`, observed buffered depths from 0 to the unchanged capacity of 64)
and `run_loop_timing` (`save` and `classification`). Each timing has `last_ns`,
`max_ns`, a saturating `count` and a nullable `max_at` timestamp, with no sample
history. Queue depths keep the numeric `alf` and `netfilter` values and add
`max_at: {alf, netfilter}` for their nullable timestamps. Timestamps record the
first observation of a strictly higher maximum; ties leave them unchanged.
Timing timestamps are completion times; queue timestamps are observation times.
Old states retain unknown (`null`) timestamps until a new maximum is observed.
Classification timing
covers actual classifier calls (rules/kNN/backend), not parsing, signer
inspection or deduplicated repeats. Save timing covers the whole save attempt,
including state and daily-file writes; a flush that saves uses the same timing,
while a skipped flush adds no sample. The completed duration is persisted by the
next save, including failed attempts: the last save on shutdown cannot include
its own full duration without another write. Queue high-water values, timing
counters and maxima accumulate across runs, together with their timestamps.
Text status displays the same measurements as durations and their maxima times. In
`state.json`, these fields live under `health.line_queue_high_water`,
`health.save` and `health.classification`. These observations do not measure
upstream log loss or establish the cause of stalls.
`digest` reads retained new-item events grouped by proposed label and app.
`digest --json --split` (`--split` requires `--json`) instead puts each event
in the window into at most one bucket, precedence first:
`real_deny` holds every non-nettop event whose verdict is deny, denied, block,
blocked or drop (any case), whatever its label; `known_fp` holds `decide`
events of three known false-positive causes (`nettop_policy_raw_ip`,
`alf_unknown_or_allow_decide`, and `loopback_ssh_limactl_knn` for kNN-decided
loopback rows of ssh or limactl), each with a count and its rows;
`needs_review` holds every other `decide` event. Noise and digest events that
are not denies appear in no bucket. The output also carries `health` (the
`status` report) and `window`: since, as_of, first/last event time, event
count, `coverage_gaps`, `coalesced_short_stalls`, `evicted_through`, `coverage_evicted_through` and
`truncated`. `run` records coverage spans in state: a span opens when collection
starts and ends at its last save, or when the ALF log stream ended if that came
first. `coverage_gaps` lists disjoint intervals in [since, as_of], each with
`from`, `to` and `kind`:

- `not_running`: no watcher was recorded running, including a late start, a
  real stop or restart, and a tail beyond the save grace.
- `stall`: the collector's line queue was full. The feeder applies backpressure
  without dropping the queued line; lines are delayed and upstream loss is
  possible but unmeasured. This is not evidence of a watcher restart.
- `coverage_evicted`: coverage history was dropped; the interval is unknown,
  rather than evidence that the watcher stopped.
- `legacy_unknown`: both bounding ALF spans contain pre-marker history whose
  stall causes were not reliably recorded. Consumers must treat this as
  unknown history; it is not evidence of a watcher stop or restart.

Precedence is `coverage_evicted` > `stall` > covered > `legacy_unknown` >
`not_running`.

Exact stalls are persisted as the preceding coverage span's optional
`stall_after: {from, to}`, including open stalls up to the save or collector
end. Long stalls and actual run boundaries stay exact. When the coverage or
pending-feeder history exceeds `max_entries`, recorded stalls shorter than
**one second** are coalesced into the span's `short_stalls` and
`short_stalled_ns` counters (saturating count and total nanoseconds); these
short stalls no longer create individual split gaps after compaction. Detail
is retained until this pressure occurs. A window intersecting an ALF span with
coalesced stalls remains conservatively `truncated`, because their precise
positions are no longer retained. The split window exposes
`coalesced_short_stalls: {count, stalled_ns}` as saturating sums of the whole
ALF spans intersecting the window. These are per-span sums, so they may include
stalls just outside the window; netfilter spans are excluded. A clean window
has both counters zero. A window with only coalesced stalls has an empty
`coverage_gaps` array, positive counters and `truncated: true`.
Counts describe delayed collection, not
measured loss. Both coverage spans and pending feeder records are bounded by
`max_entries`; `max_state_bytes` still bounds persisted state. Coalescing never
bridges a real stop or another source. If count or age retention must still
drop spans or pending records, `coverage_evicted_through` records the newest
end of discarded history (including any following stall). It is persisted in
state and exposed beside `evicted_through` in the split window (`null` if no
known eviction). Time before this watermark is conservatively
`coverage_evicted`, even where retained spans overlap it. The watermark covers
history discarded from either collector; split coverage itself uses ALF spans.
Spans are kept in start-time order. Pruning drops the oldest history while
preserving the newest span of each running source, including across compaction.
That open span stays separate from coalesced history, so past short stalls do
not mark later complete windows as truncated. A compacted pending batch closes
its counter-bearing span at the batch's last resume time; later saves extend a
separate clean span. Windows starting at or after that boundary inherit none
of the batch's counters.
If `max_entries` is smaller than the number of running sources, the hard bound
still applies: an evicted open span is retained in its runtime tracker and
restored and extended on the next save. Its discarded time advances the same
watermark, so it is unknown rather than reported as a stop. The runtime snapshot
is not persisted; a new watcher run opens new coverage as usual.

When a span reaches the window, its end may trail as_of by up to
`nettop_interval` + `save_interval`, the unchanged expected save cadence,
without an unrecorded tail gap. A watcher that died within that interval is
not detected, and a save delayed longer can add a spurious tail gap. Explicit
stalls never receive this grace. Without a span reaching the window, all
unrecorded time is a gap whatever its length. When a state file without
`coverage_version` loads, all existing spans are marked `legacy: true` and
the in-memory version becomes 1; the next save persists both. Newly collected
spans are not legacy. Gaps bounded by two legacy ALF spans are
`legacy_unknown`, including when the bounds lie outside the digest window.
The gap from legacy history to the first new-format run remains `not_running`
because that boundary records a real restart. Compaction preserves `legacy`
if either merged span has it; pruning preserves retained flags and marks
discarded history with the eviction watermark. No historical cause or
watermark is inferred. Saving and reloading versioned state preserves the
flags without marking new spans legacy. No configuration fields change.

`evicted_through` keeps its existing meaning: the newest timestamp of any event
pruned by `retention_days` or `max_entries`. `truncated` is set for any coverage
gap, either eviction watermark at or after since, or an intersecting span with
coalesced short stalls: part of the window may be missing. A health timestamp
proves only that state was saved then, not complete collection.
Ordinary repeats update counters/last_seen silently. Rules run again on each
repeat's latest bytes and current signer; each newly triggered `decide` rule ID
emits one escalation per key, recorded in state across restarts. A further repeat
of the same rule stays silent.
A deny spike emits one additional event per key per fixed window starting at
its first deny (threshold is inclusive). Dedup keys contain source, app,
verdict, port, and remote class; different subnets within one class collapse.

### Explicit configuration

Every field below is required; there are no implicit behaviour defaults.
The numbers here are examples, not recommended production policy. All paths
must be absolute. The config must be a regular file owned by the invoking
user and must deny group/world writes. Unknown fields and trailing JSON are
refused. The former `port` field is removed and refused as unknown.
`novelty_similarity` must be finite and in `(0, 1]`.

```json
{
  "schema": "mac-infra.firewall-watch/v1",
  "state_dir": "/ABSOLUTE/state",
  "max_entries": 10000,
  "retention_days": 14,
  "nettop_interval": "30s",
  "save_interval": "10s",
  "signer_failure_ttl": "30s",
  "max_state_bytes": 33554432,
  "max_model_bytes": 2147483648,
  "deny_spike_count": 10,
  "deny_spike_window": "5m",
  "k": 3,
  "novelty_similarity": 0.5,
  "classifier_timeout": "120s",
  "llama_server": "/opt/homebrew/bin/llama-server",
  "model": "/ABSOLUTE/Qwen3-Embedding-0.6B-Q8_0.gguf",
  "model_sha256": "06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439",
  "labelled_pool": "/ABSOLUTE/fixtures-v1.jsonl",
  "netfilter_source": false,
  "netfilter_journal_dir": "/ABSOLUTE/netfilter-journal"
}
```

`netfilter_source` (required boolean) adds a third collector source to `run`:
the per-flow log of the netfilter content-filter system extension
(`apps/netfilter`).
- Input: the watcher reads `log stream --style ndjson --level info` for subsystem
  `works.relux.mac-infra.netfilter`, category `flow`.
- Sender check: any process can log under that name, so a line is accepted
  only when logd records its process and sender image as the installed
  extension under `/Library/SystemExtensions/<UUID>/` and the sender runs as
  root. Other lines count as `netfilter_rejected_sender` in `status`.
- Parsing: event JSON with unknown keys, bad enums, out-of-range ports, invalid
  hostnames or unbounded text counts as `netfilter_invalid` and is dropped.
- Item mapping: direction becomes the kind; the app path (else signing id)
  becomes the app; the signing facts become the signer (`Apple`,
  `Team: <ID>`, `ad-hoc`, `unsigned`, `unknown`).
- Destination: a named flow to a public address is `internet`, and its bucket
  is the registrable name; a bare public IP is `internet-raw-ip`.
- Dedup: the destination is part of a netfilter item's dedup key, so a new
  destination for an app is a new item. Events keep `kind` and `host`.
- Rule: netfilter ad-hoc or unsigned outbound flows to the internet trigger
  `policy_unsigned_outbound`.
- Coverage: the stream has its own coverage spans (`source: "netfilter"`).
  Its end does not stop the watcher; `status` then shows `netfilter_error`.
  The digest window's gaps still come from the ALF spans only.
- Reconciliation: the stream also carries the extension's enforcement
  actions (category `action`, same sender check). Every kill, block or
  unblock the extension applied must follow a journaled intent in
  `netfilter_journal_dir` (required absolute path) from the same actor and
  target, at most two minutes earlier. Otherwise the watcher journals a
  `reconcile_mismatch` alarm. Refused actions never alarm.
- Capacity: netfilter events share `max_entries` and `max_state_bytes` with
  ALF and nettop events. Every new destination of an app is a new item, so
  raise both before enabling the source. When the shared cap evicts ALF
  events, the digest window reports it (`evicted_through`, `truncated`).

`max_entries` independently caps dedup entries, signature cache entries, and
retained events in total across all daily files. Dedup/events also expire by
`retention_days`. Oldest last_seen dedup entries are evicted first. Evicted
items can become new again; evicted executable cache entries can be inspected
again. Signature inspection uses `/usr/bin/codesign -dv --verbose=2` on the
original bounded path held only in memory. Display/persistence uses its sanitized
form. At each lookup, lstat of the resolved real path supplies dev, inode, size,
mtime ns and ctime ns; changed identity triggers inspection. Cache keys hash the
original path and entries also bind this identity. Bundle-directory successes
are re-inspected because directory lstat does not attest changes to inner code.
Inspection failures cache
`unknown` only for `signer_failure_ttl`, measured from inspection, without
extending the deadline on hits. Missing paths, bundle IDs and process names
without paths have unknown signers. This is observation metadata, not signature
verification; an ALF allow with unknown signer gives `hard_unverified_inbound`.

`save_interval`, `signer_failure_ttl`, and all other durations are positive Go
durations. `max_state_bytes` is 1..1 GiB; `max_model_bytes` is 1..1 TiB.
`max_entries` is 1..100000 and retention is 1..3650 days. Choose a state byte
limit large enough for the retained events, dedup entries and signer cache.
Oversized/structurally corrupt state is refused with a corruption error without
rewriting it. Null maps/entries, invalid counts and invalid field bounds are
refused before pruning. A save exceeding the byte cap also fails. Stored text
fields (app, signer, unknown-message samples) are checked on load for the
persisted-text invariants: valid UTF-8, within their byte cap (1024 or 256), no
control characters. IP redaction happens once, at write time; load does not
re-run it, because a cut at the cap can leave an address-looking fragment of a
token that was not an address. Truncation never splits a UTF-8 rune.

The state directory must be owned by the caller, mode `0700`, and not a symlink.
Choose a short absolute path: Darwin UNIX socket path names must fit in 103 bytes.
`state.json`, `events-YYYY-MM-DD.jsonl`, and `new-events.flag` are `0600`.
Writes use same-directory temporary files and rename. State is authoritative;
daily projections are rewritten atomically only when their events changed,
recovering projections after an interrupted write. New-key, spike and escalation
events save immediately. Silent updates mark state dirty, then save at
`save_interval`, the next nettop tick if earlier, and shutdown. The flag contains
the latest event RFC3339 timestamp. A per-directory advisory lock is acquired
before loading state and refuses concurrent collectors.
Directory ancestors and same-user concurrent replacement are not a security
boundary. The files do not form a multi-file transaction, and sudden power
loss durability is not guaranteed by rename alone.

Direct watcher artifacts are under `state_dir`, including the private UNIX
socket and lock. `MkdirAll` may also create missing ancestor directories above
that leaf. stdout/stderr write to the caller's destinations; the plist chooses
separate files under the state directory. These streams need operator rotation.
The selected llama-server binary is a trusted input and is not sandboxed or
hash-pinned. The watcher's inherited environment is also a trusted input to
its own runtime. Collector/codesign children receive only `PATH=/usr/bin:/bin`
and `LANG=C`; llama-server receives an empty environment, so inherited loader
and `LLAMA_ARG_*` settings cannot steer it. The watcher does not guarantee all
filesystem/network side effects of an arbitrary trusted backend executable.

Raw peer IPs are never emitted or persisted. IPv4 peers become `/24`, IPv6
peers `/64`; classes are `lan`, `tailnet` (`100.64/10`,
`fd7a:115c:a1e0::/48`), `loopback`, and `internet-raw-ip`. IP literals in names
and unknown message samples are redacted as well. Samples mask digits and
are bounded to 16 templates of 256 bytes. Invalid/truncated/oversize JSON
increments a separate counter; unknown `fw` shapes are counted and sampled.

### Proposals and limits

Hard rules precede policy: inbound allow by unsigned/ad-hoc/no-designated-
requirement code, ALF allow with unverified/unknown signer
(`hard_unverified_inbound`), every non-allow ALF verdict (including unknown),
and deny spikes propose `decide`. Nettop's `observed` sentinel is traffic observation,
not an ALF allow verdict. Policy branches preserve the supplied benchmark's
ordering, with rule IDs, and also recognize versioned interpreter names.
The labelled embedding pool is loaded in memory at startup. Weighted kNN uses
the benchmark instruction prefix and feature rendering, cosine similarity,
and riskier-label tie breaking (`decide` > `digest` > `noise`). Only neighbours
among the top-k whose cosine similarity is >= `novelty_similarity` vote, with
that positive similarity as weight. Sub-threshold neighbours cast no vote.
Only a label with at least one qualifying vote can win; if none qualifies,
the proposal is `decide`/`novel`. Timeout, invalid response, or embedding failure
gives `decide`/`classifier_unavailable`, never `noise`; deterministic rules still
work. Startup errors (including hash mismatch or an unsafe/live socket) refuse `run`
and `classify` with exit 1. Pool failures leave the deterministic observer
running with unmatched proposals failing to decide; it retries pool loading
on nettop ticks. Item text is data; injection-looking names do not alter rules.

The fixture scores are **synthetic and self-labelled by the policy author**;
they are not evidence of accuracy on real host traffic. The copied policy is
in `internal/security/firewallwatch/testdata/LABEL_POLICY.md`. The v1 corpus
also contains a policy inconsistency: its hidden `.local/bin/claude` example
is labelled digest while the benchmark's hidden-path rule says decide. The
implementation preserves the conservative rule.

The deny log shape has not been observed yet. Only verdict `1` is read as
allow; every other code stays `verdict_code:N`, never guessed as deny or allow.
A spike counts repeated known non-allow codes, not unknown-format log messages.
ALF lines carry no port and direction; ports come from nettop sampling, which
misses short flows. The sources are deliberately separate and are not joined
by PID or guessed direction. ALF allow observations with missing direction
can therefore reach kNN with unknown features. Nettop uses one numeric CSV
sample (`/usr/bin/nettop -L 1 -n -x -J bytes_out`) per configured interval,
including TCP/UDP rows with positive outbound bytes. This establishes outbound
traffic, not who initiated a TCP connection; cumulative byte observations are
not accurate per-interval upload deltas. Public numeric peers conservatively
have class `internet-raw-ip` even when the app originally used DNS. Unknown
CSV rows are counted; DNS-only and malformed endpoints never become flows.
The stream is `/usr/bin/log stream --style ndjson --info --predicate
'subsystem == "com.apple.ALF.ApplicationFirewall"'`. If its pipe ends, the
watcher exits for the supervisor to restart; nettop errors appear in status.
The line queue is bounded and classification is synchronous, so sustained
backpressure may lose upstream log records. No firewall-state-change source,
packet capture, reverse DNS, executable-path resolution by PID, or live host
collector completeness is claimed.

### Optional model verification and LaunchAgent example

Ordinary Go tests use a UNIX-socket fake embedding service and skip the real
model test. On a host with the exact pinned model and llama-server, run:

```sh
MAC_FIREWALL_REAL_MODEL=1 go test ./cmd/mac-firewall -run '^TestWatchRealModel$' -count=1 -v
```

The test invokes the `watch classify` command path on heldout v2 with the v1
pool, `k=3`, novelty `0.5`, and timeout `120s`. It requires accuracy >=0.85 and
zero decide-to-noise errors on these synthetic, self-labelled fixtures. It
starts/reaps only its foreground child, does not sample host traffic, and
installs no service. The test pins the specified Qwen3 model path and SHA-256.

On a sandbox without Metal access, the equivalent CPU run is:

```sh
MAC_FIREWALL_CPU=1 MAC_FIREWALL_REAL_MODEL=1 go test ./cmd/mac-firewall -run '^TestWatchRealModel$' -count=1 -v
```

The CPU test uses a test-only wrapper with explicit `--device none
--n-gpu-layers 0 --no-kv-offload` argv; production never forwards ambient model
settings. On 2026-10-19, the review-fix CPU run successfully loaded the actual
pinned model through `/dev/fd/3` and authenticated its UNIX socket peer:
29/31 (93.55%), macro F1 0.9346, decide-to-noise 0; p50 146.0ms, p95 289.3ms (delivery validation run, CPU).
These are synthetic policy-author self-labels, not host-traffic guarantees.

Earlier measurement on 2026-10-19, llama-server build 10621, CPU backend: 29/31
correct (93.55%), macro F1 0.9346, decide-to-noise 0; latency p50 140.5ms,
p95 237.6ms. These fixtures are synthetic and self-labelled by the policy
author. The default Metal run failed to allocate a command queue in the
execution sandbox; setting only GPU layers to zero still initialized Metal.

Measured on 2026-10-19 on the host (M1 Max, Metal, same build and model):
28/31 correct (90.3%), macro F1 0.9009, decide-to-noise 0; latency p50
20.7ms, p95 22.0ms. The two runs differ by one row because of numerics; on
real events the accuracy is still unmeasured.

[Example LaunchAgent](../assets/works.relux.mac-firewall-watch.plist) is
**documentation only**, with `ProcessType=Background`, `KeepAlive`, and logs in
the state dir. Replace all placeholder paths; create the private state dir
and private stdout/stderr log files before any manual installation. Launchd's
stdout/stderr logs are separate from bounded event retention and need their
own operator log rotation. No installation/load/start command is provided or
executed by the watch CLI.

## Netfilter kill path (operator CLI)

The netfilter extension (`apps/netfilter`) observes by default. The kill path
is narrow and journal-first; it is off until the owner installs the
root-owned protect-list
`/Library/Application Support/works.relux.mac-infra.netfilter/protect.json`
(schema `mac-infra.netfilter-protect/v1`; each entry has exactly one of
`app_path`, `app_path_prefix`, `signing_id`, `host_suffix`, plus a `reason`).
Both loaders verify root ownership and safe modes of the file and every
ancestor directory, refuse symlinks and multiple hard links, and read only
the verified file descriptor; a refusal leaves enforcement off.
The "danger" policy belongs to the operator (the local-sysadmin keeper). The
classifier never kills on its own.

```sh
mac-firewall netfilter kill    --journal-dir DIR --protect-list FILE --app-binary /Applications/NetFilter.app/Contents/MacOS/NetFilter --actor A --reason R (--flow ID | [--app P] [--host H] [--port N])
mac-firewall netfilter block   ... --actor A --reason R [--app P] [--host H] [--port N] --for 30m
mac-firewall netfilter unblock ... --actor A --rule ID
mac-firewall netfilter reported --journal-dir DIR --actor A --ref SEQ --event EVENT_ID
mac-firewall netfilter alarm   --journal-dir DIR --actor A --reason R [--app P] [--host H] [--port N]
mac-firewall netfilter warning --journal-dir DIR --actor A --reason R [--app P] [--host H] [--port N]
mac-firewall netfilter list    --app-binary PATH --actor A
mac-firewall netfilter status  --journal-dir DIR --app-binary PATH
```

- Every path is an explicit flag. Output is JSON. Exit 0 ok, 1 refused or
  failed, 2 usage.
- Order for kill, block and unblock:
  1. Protect-list check: a missing or invalid list refuses; a protected
     target refuses with nothing journaled or sent.
  2. The intent is journaled and fsynced. If that write fails, nothing is
     sent.
  3. The signed app forwards the request to the extension over XPC.
  4. The result is journaled.
  5. For an applied kill or block, a `report_pending` entry is journaled
     and `incident_ru` holds the Russian owner post: what, app, where, why,
     who, undo, and the journal seq/hash as an external anchor. The
     operator posts it with its own identity and then runs `reported`,
     which journals `report_done`. If the post fails, the kill stands and
     the report stays pending.
- `alarm` and `warning` only journal the operator's detections (D7: "the
  alarm must fall into the journal"). They act on nothing.
- Hosts are journaled lowercased, as the extension reports them.
- Blocks drop new matching flows until the expiry (at most 24 h, in memory
  only: an extension restart clears them). `unblock` removes one early.
- Journal (`internal/security/journal`): a ring of 10,000 entries of at most
  1 KiB each (warnings, alarms, kills, blocks, undos and report state only,
  never flows). It has monotonic seq numbers and a SHA-256 chain within the
  window, an owner-only directory, and atomic compaction. `status` reports
  `chain_ok`, the last seq/hash and `reports_pending`.
