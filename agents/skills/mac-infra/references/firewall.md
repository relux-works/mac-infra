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
llama-server child on numeric IPv4 loopback only, with proxies and HTTP redirects
refused. The pinned model SHA-256 is verified before starting that child.

```sh
mac-firewall watch run --config /ABSOLUTE/firewall-watch.json
mac-firewall watch digest --config /ABSOLUTE/firewall-watch.json --since 24h
mac-firewall watch digest --config /ABSOLUTE/firewall-watch.json --since 24h --json
mac-firewall watch status --config /ABSOLUTE/firewall-watch.json --json
mac-firewall watch classify --config /ABSOLUTE/firewall-watch.json --fixtures /ABSOLUTE/fixtures-v2-heldout.jsonl --json
```

`run` stays in the foreground. SIGINT/SIGTERM stop collection and reap its
llama-server child. Exit codes are 0 success, 1 refused/failed, 2 bad usage.
`status` reports last persisted backend health with its observation time, not
a live health probe; a stale timestamp may mean the watcher has stopped.
`digest` reads retained new-item events grouped by proposed label and app.
Repeats update state counters/last_seen without producing another item event.
A deny spike emits one additional event per key per fixed window starting at
its first deny (threshold is inclusive). Dedup keys contain source, app,
verdict, port, and remote class; different subnets within one class collapse.

### Explicit configuration

Every field below is required; there are no implicit behaviour defaults.
The numbers here are examples, not recommended production policy. All paths
must be absolute. The config must be a regular file owned by the invoking
user and must deny group/world writes. Unknown fields and trailing JSON are
refused. Port is an integer in 1..65535, always bound to `127.0.0.1`.

```json
{
  "schema": "mac-infra.firewall-watch/v1",
  "state_dir": "/ABSOLUTE/state",
  "max_entries": 10000,
  "retention_days": 14,
  "nettop_interval": "30s",
  "deny_spike_count": 10,
  "deny_spike_window": "5m",
  "k": 3,
  "novelty_similarity": 0.5,
  "classifier_timeout": "120s",
  "llama_server": "/opt/homebrew/bin/llama-server",
  "model": "/ABSOLUTE/Qwen3-Embedding-0.6B-Q8_0.gguf",
  "model_sha256": "06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439",
  "labelled_pool": "/ABSOLUTE/fixtures-v1.jsonl",
  "port": 18191
}
```

`max_entries` independently caps dedup entries, signature cache entries, and
retained events in total across all daily files. Dedup/events also expire by
`retention_days`. Oldest last_seen dedup entries are evicted first. Evicted
items can become new again; evicted executable cache entries can be inspected
again. Signature inspection runs once per cached executable path, with
`/usr/bin/codesign -dv --verbose=2`. Bundle IDs and process names without paths
have unknown signers; this is observation metadata, not signature verification.

The state directory must be owned by the caller, mode `0700`, and not a symlink.
`state.json`, `events-YYYY-MM-DD.jsonl`, and `new-events.flag` are `0600`.
Writes use same-directory temporary files and rename. State is authoritative;
daily files are rebuilt atomically from its retained events, recovering
projections after an interrupted write. The flag contains the latest event
RFC3339 timestamp. A per-directory advisory lock refuses concurrent collectors.
Directory ancestors and same-user concurrent replacement are not a security
boundary. The files do not form a multi-file transaction, and sudden power
loss durability is not guaranteed by rename alone.

Raw peer IPs are never emitted or persisted. IPv4 peers become `/24`, IPv6
peers `/64`; classes are `lan`, `tailnet` (`100.64/10`,
`fd7a:115c:a1e0::/48`), `loopback`, and `internet-raw-ip`. IP literals in names
and unknown message samples are redacted as well. Samples mask digits and
are bounded to 16 templates of 256 bytes. Invalid/truncated/oversize JSON
increments a separate counter; unknown `fw` shapes are counted and sampled.

### Proposals and limits

Hard rules precede policy: inbound allow by unsigned/ad-hoc/no-designated-
requirement code, every non-allow ALF verdict (including unknown), and deny
spikes propose `decide`. Nettop's `observed` sentinel is traffic observation,
not an ALF allow verdict. Policy branches preserve the supplied benchmark's
ordering, with rule IDs, and also recognize versioned interpreter names.
The labelled embedding pool is loaded in memory at startup. Weighted kNN uses
the benchmark instruction prefix and feature rendering, cosine similarity,
and riskier-label tie breaking. A neighbour below the explicit novelty
threshold gives `decide`/`novel`. Timeout, invalid response, or embedding failure
gives `decide`/`classifier_unavailable`, never `noise`; deterministic rules still
work. Startup errors (including hash mismatch or occupied port) refuse `run`
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

Ordinary Go tests use a loopback fake embedding service and skip the real
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
LLAMA_ARG_DEVICE=none LLAMA_ARG_N_GPU_LAYERS=0 LLAMA_ARG_KV_OFFLOAD=0 MAC_FIREWALL_REAL_MODEL=1 go test ./cmd/mac-firewall -run '^TestWatchRealModel$' -count=1 -v
```

Measured on 2026-10-19, llama-server build 10621, CPU backend: 29/31
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
