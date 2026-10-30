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
Once the run context is cancelled or owned-backend teardown starts, rows
still reached by the run loop (including the rest of a nettop sample and
repeat escalations of an existing key) are
retained as `digest` with reason `backend_shutdown`, without new backend or
signer work. Cancellation during classification uses the same reason. These
rows do not enter `needs_review`; actual non-nettop denies still enter
`real_deny`. They remain ordinary retained/deduplicated events, not pending
work to retry on the next run. A backend crash, timeout or classifier failure
while the run context is active still yields `decide/classifier_unavailable`.
Collector lines left in ALF/netfilter queues when the run loop exits are
discarded and counted in `health.shutdown_dropped_lines` in `state.json`,
also exposed as `shutdown_dropped_lines` in JSON status and split health.
Its `alf` and `netfilter` counters saturate at uint64's maximum and accumulate
across runs. They count raw lines, including a feeder's already-read line
blocked on a full queue when cancelled; one line need not be a valid event.
The final save follows feeder cleanup, so it includes these counts and the
collector's coverage end. Unread collector/pipe data and upstream log loss
are outside these counters. No configuration fields are added.
`status` reports last persisted backend health with its observation time, not
a live health probe; a stale timestamp may mean the watcher has stopped.
The persisted health also reports `line_queue_high_water` (`alf` and
`netfilter`, observed buffered depths from 0 to the unchanged capacity of 64)
and `run_loop_timing` (`save`, `classification`, `maintenance` and `journal`). Each timing has `last_ns`,
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
while a skipped flush adds no sample. Maintenance timing covers each nettop
tick's backend health check, including a classifier Init after a failed check;
old states read it as zero. Journal timing covers each state-journal append,
heartbeats included; save timing covers snapshots. The completed duration is persisted by the
next save, including failed attempts: the last save on shutdown cannot include
its own full duration without another write. Queue high-water values, timing
counters and maxima accumulate across runs, together with their timestamps.
Text status displays the same measurements as durations and their maxima times. In
`state.json`, these fields live under `health.line_queue_high_water`,
`health.save`, `health.classification`, `health.maintenance` and `health.journal`. These observations do not measure
upstream log loss or establish the cause of stalls.
`health.slow_ops` keeps the newest 512 run-loop operations that took at least
two seconds, in completion order: `kind` (`save`, `classification`,
`maintenance`, `nettop_sample` or `journal`), `at` (completion time), `duration_ns`, and
`items` when known (the rows of a nettop sample, including the time spent on
collector lines drained during it, or the labelled pool rows of a maintenance
whose Init succeeded). A `nettop_sample` is timed from the command start, so it
includes command time during which the run loop kept handling lines. A failed
or timed-out nettop command is recorded as a `nettop_sample` without `items`. Records hold no item text, hosts, apps or paths. When the
bound drops a record, `health.slow_ops_dropped_through` keeps the latest dropped
completion time. Like the timings, a save's own record persists with the next
save.
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
count, `coverage_gaps`, `coalesced_short_stalls`, `evicted_through`, `coverage_evicted_through`,
`truncated` and `slow_ops`. `slow_ops` holds the `records` that completed in
[since, as_of] (an operation counts where it completed, even if it started
earlier), per-kind `kinds` with `count`, `max_ns` and `max_at` in that window,
and `dropped_through` when the bound dropped records completed at or after
since; it does not affect `truncated`. `run` records coverage spans in state: a span opens when collection
starts and ends at its last snapshot or heartbeat, or when the ALF log stream ended if that came
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
- `write_refused`: a `not_running` gap during which a run ended because the
  writer refused a record or snapshot the reader would reject (see Clock
  steps). Its `detail` names, for each refusal in the gap (several runs can
  fail before new coverage is durable), the kind (`journal` or `snapshot`) and
  the refused check (`entry.time_order`, `coverage.span_order`,
  `coverage.stall_order` or `shape`), and says "repeated" when the same check
  was refused within the three refusals recorded before it, so a restart loop
  does not pass silently. A refusal is recorded once, also when a start fails
  or is interrupted after recording it and the marker is read again.

Precedence is `coverage_evicted` > `stall` > covered > `legacy_unknown` >
`not_running`; a `not_running` gap containing a recorded refusal is reported
as `write_refused`.

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
restored and extended on the next snapshot or heartbeat. Its discarded time advances the same
watermark, so it is unknown rather than reported as a stop. The runtime snapshot
is not persisted; a new watcher run opens new coverage as usual.

When a span reaches the window, its end may trail as_of by up to
`nettop_interval` + `save_interval`, the unchanged expected heartbeat cadence,
without an unrecorded tail gap. A watcher that died within that interval is
not detected, and a heartbeat delayed longer can add a spurious tail gap. Explicit
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
`retention_days`. Dedup and signature cache entries over the cap are evicted
in a fixed order: earliest wall-clock `last_seen` first, equal times by key,
so the same state always loses the same entry. The earlier comparison
compared two readings that both carried a monotonic clock by that clock, so
it can differ only for such readings whose monotonic and wall-clock order
differ; mixed with times loaded from `state.json`, those could make it
cyclic, with a victim that depended on map iteration. Times a run stores come
from the run clock (see Clock steps) and carry no monotonic reading, so within
a run the two orders agree, and the change there is the one-pass prune. A
refresh with a wall time earlier than the recorded `last_seen` keeps that
time (see Clock steps), so such a backward refresh cannot change the eviction
order a crash would lose. A forward silent refresh can: until it is appended
(at most `save_interval`), a crash may make that key the next victim, the
re-emit exposure described for crashes below. Events are
evicted as before, oldest timestamp first. Evicted items can become new again; evicted executable cache entries can be inspected
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
`state_dir` must be a clean absolute path: no `.` or `..` element and no
repeated `/` (trailing `/` are allowed). Every check and every use then
name the same directory, and a trailing `/` does not follow a symlink. Any
other spelling is refused when the config loads. The daily event files are
found by name inside it, so characters such as `*` or `[` in the path are never
read as a pattern.
Choose a short absolute path: Darwin UNIX socket path names must fit in 103 bytes.
`state.json`, `state-journal.jsonl`, `events-YYYY-MM-DD.jsonl` and
`new-events.flag` are `0600`. `state.json` is a snapshot; the state journal
(`state-journal.jsonl`) holds what changed since it, one JSON record per line,
each append followed by a full sync (BUG-261029-kpyw8s). Every append carries
all changes since the previous one: each entry and signer that changed or was
removed, the events added, the identities of the events its prunes removed
(time, key fields, count, label and reason kind), and its latest event and
eviction times. An append is due at once for new-key, spike and escalation
events of every source, for any change of deny-window state (window start,
deny count, spike or escalation marks) and for a new or changed signer
inspection result; `new-events.flag`, which holds the latest event RFC3339
timestamp, is updated with each append that carries events. Other changes
(last-seen times and counts, signer refreshes) and the silent state (parser
and nettop counters, errors, backend health, run-loop health, coverage) follow
in a heartbeat append once `save_interval` has passed since the last heartbeat
or snapshot completed (an urgent append does not restart that interval), on
each nettop tick and when the netfilter stream ends. The save timer counts
elapsed time, not wall time: when it fires, pending changes are written even
while the run clock holds during a backward wall-clock step, so the
`save_interval` bound below holds through a step. A change in backend health
or in held clock readings is pending too, and so is a collector report that
arrives after the heartbeat that took its line (a new queue high-water mark,
a stall, the collector's end). An idle watcher still writes these within
`save_interval`. A
heartbeat carries, of the coverage, what changed since the last snapshot, by
position: the current value of each source's open span there, and the spans
appended since. Only snapshots prune or reorder coverage, so nothing else can
change in between, and positions are independent of span times (a clock step
across a restart cannot hide a new run's span). The journal never grows past 8 MiB, nor past `max_state_bytes`
minus the snapshot's size: every record carries the values it changes, so the
state replay rebuilds always fits the watcher's startup snapshot. An append
that would cross the limit takes a snapshot instead, which refuses a state
over `max_state_bytes` as before. Before an append, the record's entries,
signers, events and coverage pass the same checks a reader applies, so an
append never acknowledges what a reader would refuse.

A snapshot rewrites `state.json` (with `journal_seq`, the last record folded
in) by a same-directory temporary file, full sync and rename, then the day
files and the flag, then syncs the directory, removes the journal and syncs
the directory again. It runs at watcher start (folding any journal left by a
crash), every 5 minutes, after 500 records, at shutdown, when a heartbeat's
coverage delta would exceed 256 spans, and after a failed append or snapshot. An append reserves
its seq before writing, so the fallback snapshot's `journal_seq` covers
whatever part of a failed append reached the disk; after a failed append
nothing more is appended until a snapshot succeeds, so a torn write can only be
the journal's last line. A crash before a snapshot's rename leaves the old
snapshot and the whole journal; after it, records up to `journal_seq` are
skipped. Day files are projections written only by snapshots, so they can lag
the journal by up to one snapshot interval; `digest` and `status` read the
journal.

Opening the store (the watcher, `status`, `digest`) opens the journal before
reading `state.json`, without following symlinks, and checks each opened file
(a private regular file of the caller, at most one link), so a rotation in
between still gives a consistent view. It then applies the records after
`journal_seq` in order, checks the result's structure, prunes entries, events
and signers, and checks the bounds. It never prunes or compacts coverage, so a
reader sees exactly the watcher's spans, gaps and truncated verdicts; replayed
coverage may exceed `max_entries` by at most one heartbeat's 256-span tail. Only complete lines count: a last line without a newline, or a last
line that is not valid JSON, is a torn tail, ignored and counted in
`health.journal_torn_tail`. Any other malformed line, a seq gap, an unknown record type, or a record whose items fail the per-item checks (each record is checked before it is applied, so a later record cannot hide an earlier corrupt one) refuses the state as corrupt. Readers never write and never create
a missing state directory: only the watcher's start-up snapshot removes a torn
tail, together with the folded journal.

After a crash the journal restores the watcher's state as of its last append:
every emitted event and deny-window change, signer results, and every other
change up to the last heartbeat, at most `save_interval` old, as full saves
did before the journal. The effect on emission is bounded by the operator's
acceptance (sysadmin decision, 2026-10-29): after a crash, a key whose latest
refresh was not yet appended (at most save_interval old) can re-emit once,
through early expiry or through count-pressure eviction choice; the same
exposure as before the journal. `TestJournalOnlyReEmitIsUnappendedRefresh`
and `TestR2UnappendedCapRefresh` pin both paths.
A shutdown takes a snapshot and removes the journal, so an older binary reads
the full state after a clean stop. After a crash, run this binary once before
rolling back, or the older binary misses the journaled records.

The nettop command runs off the run loop, one at a time: while it runs, the
loop keeps handling ALF and netfilter lines and the save timer, so a command
that runs to its timeout under a socket flood does not stall the feeders. A tick
that finds a command still running is skipped, and the tick restarts when a
sample completes, so the next command starts a full `nettop_interval` later
rather than at once. A command that outlives its timeout (`nettop_interval`) is
killed by its own PID only; its partial output is discarded, it records
`nettop_error`, emits nothing and is recorded as a `nettop_sample` without
items. On shutdown a running command is cancelled and its result discarded.
Before each nettop row is classified, the sample handles the ALF and netfilter
lines already queued, at most one queue's worth per source (each source has
its own budget) and without waiting, so a sample of many slow classifications
does not hold the feeders in a stall. After cancellation the sample drains
nothing. Row collection, backend maintenance, journal appends and snapshots
still run on the run loop. Each new item that emits an event costs one journal
append with `F_FULLFSYNC`, so a flood of lines that are each a new item (for
example loopback flows to many fresh ports) is handled at the speed of those
appends, tens of lines per second, and can still stall the feeders. An observation decides only its own key's retention: an entry last
seen before the cutoff counts as new. Entries, events and coverage spans nobody
observes expire at the next snapshot. When an observation takes entries,
events or signers over `max_entries`, their retention and bound prune runs at
once; coverage is pruned and compacted only by snapshots, so between snapshots
it can briefly exceed `max_entries`. Those later prunes apply every cutoff an earlier observation had, both
by monotonic and by wall readings. A clock correction, or a save handed an
earlier time, never brings back an item an earlier observation had expired.
Under `watch run` the run clock (below) never steps back, so a later reading
never lowers the expiry cutoff an earlier one set: what an earlier reading
expired stays expired. For times that do step back (a caller of the store
passing raw readings), the first observation after the step runs one full
prune first, and its removals are appended at once.

Clock steps. `state.json` and the journal hold wall-clock times only, while
the system time daemon can set the wall clock back, by fractions of a second
and often. Every entry, event and coverage time a run stores comes
from one run clock that never runs backward (health timings and slow-operation
times are not ordered by the reader and keep the system clock): during a backward step it holds its
latest value until the wall clock passes it again, so stored times can be up
to the step size late, and `health.clock_held_readings` counts the held
readings. An entry's `last_seen` never moves back in wall time either: a
refresh earlier than the recorded `last_seen` (an entry loaded from a run
before the clock was set back) keeps it, while the count and deny state still
update (`health.clock_held_refreshes`). That entry's expiry then counts from
the recorded time, later than the refresh by at most the step; after a large
manual step back (hours), by that much. `first_seen` and `window_start` are
never moved. Before writing, the watcher checks a record or snapshot as the
reader will load it, by wall time only; one the reader would reject is refused
before anything is written, never written and never dropped silently (a
refused journal record is not replaced by a fallback snapshot, which serves
only ordinary append failures). The run then ends with an error that names the
check (stderr) and leaves
`last-write-refusal.json` in the state directory, holding only the time, the
check and the kind; the next start records it in `write_refusals` (the last
32), removes the marker, and the digest labels that restart's gap
`write_refused`. If the marker cannot be written the run still ends, and
stderr carries the refusal alone. `watch status` shows `clock_held_refreshes`,
`clock_held_readings` (as of the latest durable snapshot or journal heartbeat)
and `write_refusals` (as recorded at the latest start; an empty list when none)
in JSON, and a `clock held: … write refusals=N, latest: …` line in text. The
`health` of `watch digest --split` keeps its fields and does not include them.

Recovery of state that a backward clock step already made unreadable (a
watcher or `status` failing with `corrupt state` or `corrupt state journal`
on a build before this fix): an explicit operator action, never automatic.

```
mac-firewall watch repair --config PATH --out DIR
```

It refuses while a watcher holds the state directory's lock, when the state
directory is a symlink or `state_dir` is not a clean absolute path (see
above), when `DIR` exists, or when `DIR` resolves inside the state
directory (checked by device and inode, so a symlink or a case variant of the
path is caught). It only
reads the state directory: it copies `state.json`, `state-journal.jsonl` and
a `last-write-refusal.json` marker byte for byte to `DIR/original` with
`SHA256SUMS`, and writes to `DIR/repaired` `state.json` and the journal with
each reversed time moved forward to the time it must not precede
(`last_seen` to `first_seen` or `window_start`; a span's end to its start; a
stall that starts before the span's end shortens the covered span to the
stall's start, or to the span's own start if the stall began earlier; one that
starts after it extends back to the span's end, so the repair errs toward
unavailable coverage and never counts a recorded stall as covered; a stall's
end to its start). Records and lines it does
not change keep their bytes, and a torn journal tail is kept as the reader
treats it (an unterminated last segment, or a last complete line that is not
JSON). A journal line the reader would refuse as not a record of this journal
(not JSON, not a delta, a seq out of order, or a first record that does not
follow the snapshot's `journal_seq`) is refused, and nothing repaired is
written. It prints a JSON report of every change (an entry by a hash of
its key, never the key), whether `DIR/repaired` opens with the normal reader,
and whether a watcher start on it succeeds: the start records the marker and
saves, tried on a disposable copy with the marker that is removed afterwards.
A copy that could not be made or removed is reported separately
(`start_check_error`, naming a copy left behind), never as a start refusal or
a success. The files the install leaves in place and a save may rewrite or
remove, `new-events.flag` and the daily `events-*.jsonl`, are checked where
they are, read-only. Each one a save would refuse (not a private regular file
of the caller, mode 0600, with one link) is named in `retained_unsafe`. A flag
is named even if the next start would not yet rewrite it (no event recorded),
since a later save would. It
exits 0 only if the copy opens and starts, the check completed and
`retained_unsafe` is empty.
Installing the repaired files is a separate step in a window, with the
watcher kept stopped from the repair to the install so the copies stay
current: copy `DIR/repaired/*` into the state directory (it stays the
caller's, mode 0700; the files are regular, mode 0600), keep `DIR/original`,
and leave `last-write-refusal.json` in place, since the next start records it
as refusal evidence. A file named in `retained_unsafe` is fixed first: set a
regular file of the caller to mode 0600, or move a symlink, a hard-linked file
or a directory with such a name aside (a save rebuilds the flag and the day
files from `state.json`).
Then start the watcher and check `watch status`.

A per-directory advisory lock is acquired before loading state and refuses
concurrent collectors. Directory ancestors and same-user concurrent replacement
are not a security boundary. The files do not form a multi-file transaction,
and sudden power loss durability is not guaranteed by rename alone.

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
