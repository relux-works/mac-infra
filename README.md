# mac-infra

macOS operations tooling and agent skills for local workstation maintenance.

## Tools

| Tool | Purpose | Command | Artifacts |
| --- | --- | --- | --- |
| `mac-audio-reset` | Diagnose and reset CoreAudio glitches without rebooting the Mac | `mac-audio-reset diagnose`, `mac-audio-reset reset --dry-run`, `mac-audio-reset reset` | none; diagnostic output only |
| `mac-audio-sweep` | Generate and play local frequency sweeps without streaming-platform compression or silent sample-rate mismatch | `mac-audio-sweep device`, `mac-audio-sweep tui`, `mac-audio-sweep tui --rerender`, `mac-audio-sweep generate --out .temp/mac-audio-sweep/sweep.wav` | cached TUI WAVs in `.temp/mac-audio-sweep/cache/*.wav`; one-shot/generated WAVs under `.temp/mac-audio-sweep/` unless `--out` points elsewhere |
| `mac-load-profile` | Capture read-only CPU, memory, process, thermal, pressure, disk, and network diagnostics | `mac-load-profile capture`, `mac-load-profile snapshot`, `mac-load-profile inspect sing-box`, `mac-load-profile tunnel`, `mac-load-profile anyconnect`, `mac-load-profile fsevents` | `.temp/mac-load-profile/capture-*`, optional `sample-*.txt` |
| `mac-video-profile` | Diagnose macOS video/display smoothness loss, WindowServer/GPU pressure, and Docker/VM rendering load | `mac-video-profile snapshot`, `mac-video-profile capture --logs` | `.temp/mac-video-profile/capture-*` |
| `mac-disk-profile` | Profile disk usage and explain heavy paths without deleting files | `mac-disk-profile scan PATH`, `mac-disk-profile top PATH`, `mac-disk-profile explain PATH` | optional JSON artifact via `--json PATH` |
| `mac-cleanup` | Plan allowlisted cleanup candidates and clean unsupported CoreSimulator runtimes only when explicitly requested | `mac-cleanup scan`, `mac-cleanup target PATH`, `mac-cleanup xcode`, `mac-cleanup xcode-runtimes`, `mac-cleanup permissions`, optional `--json PATH` | optional Plan JSON/report files under `.temp/mac-cleanup/` |
| `mac-safari-session` | Guarded, window-exact authenticated Safari page access and finite named keepalives without exporting browser secrets | `mac-safari-session open-bg URL`, guarded `run-js`/`snapshot`/`fetch-file`, `heartbeat start\|restart\|status\|list\|stop`, explicit `focus --window-id ID` | private temporary JS under `.temp/mac-safari-session/`; optional `0600` artifacts; heartbeat state/logs and one stable launcher under `~/Library/Application Support/mac-infra/browser-session/` |
| `mac-chrome-session` | Guarded exact Chrome tab access, explicit exact-tab handoff, trusted form input and native file upload, sealed authenticated same-origin downloads and Slack reads, bounded extraction, and finite named Chrome/Safari heartbeats without focus churn | `mac-chrome-session list`, guarded `run-js`/`fetch-file`/`slack-read`/`extract`, explicit `focus`, `trusted-input`, or `upload` with exact IDs/origin plus `--human-authorized`; upload/trusted input and protected fetch requests arrive through `--request-stdin`; `heartbeat start\|restart\|status\|stop\|list`, exact `close` | atomic private `run-js --out` and `fetch-file --out` artifacts; protected resource URLs, trusted values, and upload source paths stay out of argv and normal output; upload uses a short-lived private staging directory and reports only guarded origin, accepted basenames, and count; other private outputs and heartbeat state use the paths described below |
| `mac-browser-site` | Token-efficient agent-facing `q`/`grep`/`m` facade over declared Chrome/Safari site adapters | `mac-browser-site q --adapter FILE --format compact 'list(take=20) { id title }'`, `mac-browser-site grep --adapter FILE --format compact PATTERN`, `mac-browser-site m --adapter FILE --format compact --dry-run\|--confirm 'invoke(name=ACTION)'` | projected, PII-depersonalized, secret-checked `0600` JSONL under `~/Library/Application Support/mac-infra/browser-site-cache/<site>/`; no raw recognized personal data, cookies, browser storage, authorization material, or cursor/session state |
| `mac-document-sanitize` | Extract document text and redact common personal data or secrets before agent inspection | `mac-document-sanitize --json PATH`, optional `--redact-from PRIVATE_DICTIONARY` | hash-named `*.sanitized.txt` and `*.redaction.json` files under `.temp/mac-document-sanitize/` by default |
| `mac-infra-core` | Privileged LaunchDaemon helper plus user-scoped controls for allowlisted macOS maintenance actions | `mac-infra-core request-permissions sudo`, `mac-infra-core install`, `mac-infra-core status`, `mac-infra-core sleep-prevention enable\|disable\|status`, `mac-infra-core display-sleep-prevention enable\|disable\|status`, `mac-infra-core idle-lock-prevention enable\|disable\|status`, `mac-infra-core anyconnect-cleanup`, `mac-infra-core fseventsd-restart [--force]`, `mac-infra-core fseventsd-watchdog enable\|disable\|status`, `mac-infra-core uninstall` | daemon files under `/Library/LaunchDaemons/` and `/var/run/`; display and fseventsd-watchdog LaunchAgents under `~/Library/LaunchAgents/`; idle-lock restore snapshot and fseventsd-watchdog state under `~/Library/Application Support/mac-infra/` |
| `mac-keyvault` | Create, list, describe, export, sign with, verify against, rotate, annotate, and delete non-extractable P-256 key pairs in the login keychain; every item is a schema-2 record addressed as `<service>/<purpose>` (+ `--kind`, `--version`) under the derived label `works.relux.mac-keyvault.<kind>.<service>.<purpose>.v<N>`; `--enclave` fails explicitly on an unprovisioned binary | `mac-keyvault [--json] init --service S --purpose P [--title T] [--usages sign,verify] [--extraction none\|human\|agent] [--meta k=v]`, `list [--service S] [--kind K]`, `describe S/P [--version N]`, `pub S/P [--out FILE] [--format spki-der\|spki-pem\|jwk]`, `sign S/P --digest HEX\|@FILE \| --data-file F \| --stdin [--raw] [--out FILE]`, `verify S/P \| --spki FILE --digest ... --sig HEX\|@FILE [--raw] [--allow-high-s]`, `rotate S/P`, `meta get\|set\|unset S/P ...`, `delete S/P --confirm [--version N]`, `signer serve --address S/P [--kind K] [--version N]` (JSON lines on stdin/stdout, contract 1, for kvctl; Go client `internal/keyvault/signerclient`) | keychain items only; `signer serve` writes one hello line then one response line per request and exits 0 on EOF; `pub --out` writes a `0600` file; `~/Library/Application Support/mac-infra/keyvault/init.lock` serialises creates |
| `/usr/bin/textutil` | Extract text from HTML, RTF, DOC, and DOCX inputs for sanitization | invoked internally by `mac-document-sanitize` | no intermediate raw-text artifact |
| `pdftotext` | Extract PDF text for sanitization | installed with `brew install poppler`; invoked internally by `mac-document-sanitize` | no intermediate raw-text artifact |
| `go test` | Verify Go command planning and CLI behavior | `go test ./...` | test cache only |
| `scripts/setup.sh` | Build the CLIs and install global skill symlinks | `./scripts/setup.sh` | `bin/mac-audio-reset`, `bin/mac-audio-sweep`, `bin/mac-load-profile`, `bin/mac-video-profile`, `bin/mac-disk-profile`, `bin/mac-cleanup`, `bin/mac-safari-session`, `bin/mac-chrome-session`, `bin/mac-browser-site`, `bin/mac-document-sanitize`, `bin/mac-infra-core`, `bin/mac-keyvault`, `~/.local/bin/*`, `~/.agents/skills/mac-infra`, `~/.codex/skills/mac-infra`, `~/.claude/skills/mac-infra` |
| `scripts/deinit.sh` | Remove user-level installation without stranding managed jobs | `./scripts/deinit.sh` | stops all `works.relux.mac-infra-browser-heartbeat.*` LaunchAgents and removes the stable launcher plus legacy pinned copies before removing binary symlinks and the runtime skill copy |
| `/usr/bin/codesign` | Give the shared heartbeat launcher a complete stable designated identity so macOS Automation consent can retain it across rebuilds | invoked by `scripts/setup.sh`; verify with `codesign --verify --strict "$HOME/Library/Application Support/mac-infra/browser-session/bin/mac-browser-heartbeat-launcher"` | signs `bin/mac-chrome-session`; setup atomically installs those signed bytes at the single managed launcher path |

## Privacy-Safe Document Intake

Sanitize a local document before an agent reads or persists its extracted text:

```bash
mac-document-sanitize --json documents/raw/input.docx
```

The command treats the source as read-only, keeps extracted raw text in memory,
and writes two private (`0600`) artifacts by default:

- `.temp/mac-document-sanitize/document-<sha256>.sanitized.txt`
- `.temp/mac-document-sanitize/document-<sha256>.redaction.json`

The output name is content-hash based so a sensitive source filename is not
copied into the artifact name. The report contains only extraction metadata,
category counts, and warnings; it never stores matched values.

Supported inputs are TXT, Markdown, JSON, XML, YAML, CSV, TSV, HTML, RTF, DOC,
DOCX, PDF, and XLSX. HTML/RTF/Word extraction uses macOS `textutil`; PDF uses
`pdftotext` from Homebrew `poppler`; XLSX extraction is built in. Legacy XLS and
ODS files must first be exported as XLSX, CSV, or TSV.

Automatic redaction covers labeled and tabular names, email addresses, phone
numbers, residential/postal addresses, dates of birth, passports, SNILS,
12-digit personal tax IDs, valid payment-card numbers, IP addresses, JWT-like
secrets, and sensitive JSON keys. Repeated values receive stable placeholders.
For known project-specific values that heuristics miss, pass a private
one-value-per-line dictionary:

```bash
chmod 600 .temp/mac-document-sanitize/extra-redactions.txt
mac-document-sanitize \
  --redact-from .temp/mac-document-sanitize/extra-redactions.txt \
  documents/raw/input.pdf
```

For authenticated browser downloads, keep the raw file task-scoped, sanitize it
immediately, and inspect only the returned `sanitized_path`:

```bash
mac-safari-session fetch-file \
  --page "https://example.com/private/page" \
  --origin "https://example.com" \
  --resource "/api/private/file.pdf" \
  --out .temp/mac-document-sanitize/raw.pdf
mac-document-sanitize --json .temp/mac-document-sanitize/raw.pdf
```

Redaction is deterministic but heuristic, not a legal guarantee of anonymity.
Review the sanitized output before external disclosure and use `--redact-from`
for known values when necessary.

## Sleep Prevention Workflow

Inspect the current policy without changing it:

```bash
mac-infra-core sleep-prevention status
```

The status command reads the one system-wide `SleepDisabled` value from `/usr/bin/pmset -g`. Output reports `sleep_prevention: enabled`, `disabled`, or `unavailable` and `applies_to: AC,battery`. AC and battery do not have independent `disablesleep` values; the coverage line describes the two power sources governed by the global setting.

Enable or disable the persistent policy only when that change is intended:

```bash
mac-infra-core sleep-prevention enable
mac-infra-core sleep-prevention disable
```

These mutations route through the root LaunchDaemon and can execute only `/usr/bin/pmset -a disablesleep 1` or `/usr/bin/pmset -a disablesleep 0`. The setting remains in effect after the command exits until it is explicitly changed; it is not a temporary `caffeinate` assertion. Neither action changes ordinary `sleep` timers, standby, `hibernatemode`, or `displaysleep`. The display can still turn off while system sleep prevention is enabled.

`scripts/setup.sh` installs the user-level binary and skill but does not restart an already running privileged daemon. After the first setup and after every `mac-infra-core` binary update, install/reinstall the daemon before using `enable` or `disable`:

```bash
./scripts/setup.sh
mac-infra-core request-permissions sudo
mac-infra-core install
mac-infra-core sleep-prevention status
```

## Separate Display And Idle-Lock Prevention

System sleep, display sleep, and automatic screen saver start are independent
policies. Inspect or change each one separately:

```bash
mac-infra-core sleep-prevention status
mac-infra-core display-sleep-prevention status
mac-infra-core idle-lock-prevention status

mac-infra-core display-sleep-prevention enable
mac-infra-core idle-lock-prevention enable
```

`display-sleep-prevention enable` installs a current-user LaunchAgent that keeps
one `/usr/bin/caffeinate -d` assertion alive. The assertion prevents idle display
sleep on AC and battery while that user session is logged in. It does not change
`pmset` timers, system sleep, UPS policy, or other assertions. `disable` boots
out the LaunchAgent and removes its plist, so there are no timer values to
restore and no sudo requirement.

`idle-lock-prevention enable` prevents the automatic screen-saver trigger that
leads to idle Lock Screen. Internally it captures the current user's ByHost
`com.apple.screensaver idleTime`, then sets it to `0`. `disable` restores the
captured value or removes the key when it was originally absent. This command
runs as the current user and does not need the privileged daemon.

Enable both display sleep and idle-lock prevention to eliminate the two idle
triggers that lead to automatic Lock Screen. The commands deliberately do not call
`sysadminctl -screenLock off`: manual Lock Screen remains available and the
existing password-after-lock policy remains unchanged.

## Audio Sweep Workflow

Use this when you need a local hearing or output-chain frequency sweep and do not want YouTube or another streaming path to compress, resample, or filter the signal.

```bash
mac-audio-sweep device
mac-audio-sweep tui
mac-audio-sweep tui --rerender
mac-audio-sweep generate --out .temp/mac-audio-sweep/manual-sweep.wav
```

Defaults generate a 96 kHz, 16-bit PCM WAV from 1 Hz to 44 kHz. The first low-frequency ramp goes from 1 Hz to 50 Hz over 90 seconds, starting near +1 Hz per 5 seconds and then accelerating smoothly before the high-frequency exponential sweep. The TUI shows the current frequency, slope, elapsed time, sample-rate/Nyquist limit, and supports `r` to restart and `q`, `esc`, or `ctrl+c` to exit.

`mac-audio-sweep tui` caches rendered WAVs by normalized sweep parameters under `.temp/mac-audio-sweep/cache/`. If the matching WAV exists, playback starts from the cached file; if it is missing, the tool renders it. Use `--rerender` to force overwriting the cached WAV for the same parameters, or `--no-cache` for a one-shot temporary WAV.

`44 kHz` output requires a sample rate above `88 kHz`; the default is `96 kHz`, with Nyquist at `48 kHz`. The TUI default `--output-rate set` checks the current default output device, switches it to the WAV sample rate when supported, and restores the previous rate when playback stops. Use `--output-rate strict` to refuse playback unless the device is already at the WAV rate, or `--output-rate off` to bypass this guard. Hardware, Bluetooth codecs, DACs, headphones, and macOS output paths may still filter ultrasonic content. Keep volume low: high-frequency tones can be hard to perceive while still being unsafe.

## Audio Reset Workflow

Use this when macOS audio starts crackling or distorting and restarting the player app is not enough.

```bash
mac-audio-reset diagnose
mac-audio-reset reset --dry-run
mac-infra-core install
mac-audio-reset reset
```

The reset path shuts down booted iOS simulators first, then restarts CoreAudio. This targets the common failure mode where Simulator audio, Apple Music, and high sample-rate USB or Bluetooth output leave CoreAudio in an underrun-prone state.

`mac-infra-core` is intentionally not a generic command runner. The daemon accepts only fixed JSON actions over its Unix socket and executes hardcoded absolute-path commands without shell evaluation.

When sudo credentials are needed for helper setup or privileged actions, request them through the tool itself:

```bash
mac-infra-core request-permissions sudo
mac-infra-core install
mac-infra-core status
```

This caches sudo for the current interactive session only. It does not grant Full Disk Access and does not grant permissions to Terminal, iTerm2, Cursor, VS Code, or another broad launcher.

## AnyConnect Socket Filter Cleanup

Use this when Cisco AnyConnect reports disconnected but `com.cisco.anyconnect.macos.acsockext` or `vpnagentd` still eats CPU/RSS.

Start read-only:

```bash
mac-load-profile anyconnect
mac-load-profile anyconnect --logs
```

Review the cleanup plan:

```bash
mac-infra-core anyconnect-cleanup
```

Apply only after confirming AnyConnect is disconnected:

```bash
mac-infra-core anyconnect-cleanup --apply
```

The apply path is an allowlisted `mac-infra-core` action. It verifies `vpn status` is disconnected, terminates the Cisco socket-filter extension process, and restarts `com.cisco.anyconnect.vpnagentd` through `launchctl kickstart`. It refuses to run while AnyConnect appears connected unless `--force` is passed explicitly.

## Load Profiling Workflow

Use this when the Mac is hot, fans are up, UI is sluggish, or a process appears to be eating CPU or memory.

```bash
mac-load-profile capture
mac-load-profile snapshot --top 20
mac-load-profile inspect sing-box
mac-load-profile tunnel
```

`capture` writes a broad read-only artifact bundle under `.temp/mac-load-profile/capture-*`. It includes process, CPU, memory, pressure, thermal, disk, network, power assertion, route, and OS/hardware evidence. It does not stop, restart, kill, or mutate processes. Use `--logs` only when recent system pressure logs are needed.

## FSEvents Bloat Workflow

Use this when `fseventsd` shows gigabytes of RSS or sustained CPU. It buffers
events for slow consumers (Colima `mountInotify`, sync agents) and never frees
that memory on its own; CPU tracks file-event volume (git-heavy test loops).

```bash
mac-load-profile fsevents
mac-infra-core fseventsd-restart
mac-infra-core fseventsd-watchdog enable
mac-infra-core fseventsd-watchdog enable --auto-restart
mac-infra-core fseventsd-watchdog status
```

`fsevents` is read-only and needs no sudo: it reports fseventsd against RSS/CPU
thresholds, lists known consumers from a pattern allowlist, parses
`~/.colima/*/colima.yaml` for `mountInotify`/`mounts`, and sizes `go-build*`
leftovers. `fseventsd-restart` is an allowlisted root-daemon action
(`launchctl kickstart -k system/com.apple.fseventsd`) that refuses below the
512 MB threshold unless `--force` is given; update the installed daemon with
`mac-infra-core install` first. The watchdog is a current-user LaunchAgent that
checks every 10 minutes, notifies over the threshold, and restarts only with
the opt-in `--auto-restart`. Do not renice or throttle fseventsd: dropped
events make every FSEvents client rescan the volume.

## Video Smoothness Workflow

Use this when video playback, scrolling, UI animations, or Docker/VM-heavy work
start looking discrete or slideshow-like while the Mac still responds.

```bash
mac-video-profile snapshot --top 20
mac-video-profile capture --logs
```

`snapshot` prints read-only triage for compositor, display services, GPU/media,
Docker/virtualization, and browser/Electron/video process groups. `capture`
writes a durable bundle under `.temp/mac-video-profile/capture-*` with
`summary.txt`, display/GPU topology, thermal and memory pressure, power
assertions, process snapshots, display registry state, and optional bounded
WindowServer/display/GPU/Metal/frame logs. It does not reset WindowServer, kill
apps, change refresh rate, or require privileged sampling.

## Disk Profiling Workflow

Use this when disk space is disappearing and you need DaisyDisk-style heavy path evidence in the terminal.

```bash
mac-disk-profile scan "$HOME" --depth 3 --json .temp/mac-disk-profile/home.json
mac-disk-profile top "$HOME" --limit 30
mac-disk-profile explain "$HOME/Library/Developer"
```

The profiler is read-only. It skips symlink traversal by default, deduplicates hard links, reports permission errors separately, and can exclude common generated trees unless `--no-default-excludes` is set.

## Cleanup Planning Workflow

Use this when you want cleanup candidates and totals before deciding what to remove.

```bash
mac-cleanup scan --json
mac-cleanup target --json .temp/mac-cleanup/project-plan.json /path/to/project
mac-cleanup xcode --json
mac-cleanup xcode-runtimes --json
mac-cleanup permissions
```

`scan`, `target`, and `xcode` are read-only planners. They print category, risk, default selection, byte totals, candidate counts, and reasons. If macOS denies access to protected paths, the plan continues with warnings. Avoid granting Full Disk Access to broad launchers such as Terminal, iTerm2, Cursor, or VS Code; every process launched from that app may inherit the access. `mac-cleanup permissions --open` intentionally returns `not implemented` until a dedicated narrow Full Disk Access runner exists. The optional JSON output is a versioned cleanup `Plan` written with `0600` file permissions; using `--json` without a path writes under `.temp/mac-cleanup/`.

`mac-cleanup xcode-runtimes` is a narrow exception for stale simulator runtimes: it cross-checks `xcrun simctl runtime list --json` with `xcrun simctl list runtimes`, reports only `unavailable` and `deletable` runtimes, and is dry-run by default. Pass `--delete` to remove those runtimes via `xcrun simctl runtime delete <identifier>`.

## Key Vault Workflow

`mac-keyvault` keeps P-256 key pairs in the current user's login keychain as permanent, non-extractable items whose private-key ACL trusts only the binary that created them. Every item is a **record**, not a bare label: a schema-2 JSON document stored in the item's `kSecAttrApplicationTag` (no sidecar files) with `kind`, `service`, `purpose`, `version`, `title`, `description`, `algorithm`, `store`, `extraction`, `usages`, `format`, `created`, `origin`, `issuer`, `validity` and a free `meta` map; `label`, `fingerprint`, `exposure` and `operations` are derived on every read and never stored. Uniqueness is `(kind, service, purpose, version)`; the label `works.relux.mac-keyvault.<kind>.<service>.<purpose>.v<N>` (`.v<N>` always present) is derived by the vault and never typed. Commands address items as `<service>/<purpose>` with `--kind` (default `key`) and `--version N` (default: the newest); any input that is not an address — a raw label inside or outside the prefix, a bare name — is refused as `foreign_label` (exit 3) before any Security.framework call.

```bash
mac-keyvault init --service kvctl --purpose pki-root --title "bsim test PKI root" --usages sign,verify --meta owner=alexis
mac-keyvault --json list --service kvctl        # full records + label, fingerprint, exposure, operations, findings
mac-keyvault --json describe kvctl/pki-root     # newest generation; --version 1 for one version
mac-keyvault pub kvctl/pki-root --out .temp/pki-root.pem   # .pem -> PEM, .jwk/.json -> JWK, else SPKI DER; --format spki-der|spki-pem|jwk overrides
mac-keyvault sign kvctl/pki-root --digest "$(shasum -a 256 payload.bin | cut -c1-64)" --out .temp/payload.sig   # strict DER, low-S; --raw for 64-byte r||s
mac-keyvault --json sign kvctl/pki-root --data-file payload.bin   # the tool hashes with SHA-256 and reports hash, digest, digest_source
mac-keyvault verify kvctl/pki-root --data-file payload.bin --sig @.temp/payload.sig    # exit 0 verified, 1 signature_invalid, 3 high_s_refused
mac-keyvault verify --spki .temp/pki-root.pem --digest HEX --sig HEX [--raw] [--allow-high-s]   # no vault access: any P-256 SPKI DER/PEM
mac-keyvault meta set kvctl/pki-root ticket MI-7           # meta get/set/unset; reserved record names are refused
mac-keyvault rotate kvctl/pki-root              # creates ...key.kvctl.pki-root.v2 with the record copied; the old key stays until deleted
mac-keyvault delete kvctl/pki-root --confirm --version 1   # refused without --confirm; without --version the newest generation goes
```

Error contract: every failure is `{code, message, hint, os_status}` in `--json` mode (usage errors included, on stdout with an empty stderr); text mode prints `error: <code>: <message>` and `hint: <hint>` to stderr. Exit codes: `0` ok, `1` operational failure (`not_found`, `missing_entitlement` for OSStatus -34018, `security` for any other Security.framework status, `failure` for I/O), `2` `usage`, `3` policy refusal (`foreign_label`, `duplicate`, `confirmation_required`, `metadata_unknown`, `invalid_service`, `invalid_purpose`, `invalid_kind`, `unsupported_kind`, `invalid_algorithm`, `unsupported_algorithm`, `invalid_usages`, `invalid_format`, `invalid_extraction`, `invalid_generate`, `invalid_meta`, `invalid_title` (80 characters, counted as code points), `invalid_issuer` (only a certificate carries an issuer; a key record with a non-null issuer is refused on init and never reproduced by rotate), `invalid_validity`). Usage errors cover every command, `version` and `help` included, and `--meta-json` / `meta set --json-value` accept exactly one JSON document — a trailing second document or token is `usage`, exit 2, before any Security.framework call. `--json` is detected with the same `flag` parser the commands use, so every spelling `flag.Bool` accepts (`--json`, `-json`, `--json=1`, `--json=TRUE`, `-json=t`, ...) selects the envelope before or after the command, a later `--json=false` wins, and `--` ends flag parsing; the one stated bound is a token consumed as the value of a string flag (`--out --json`), which the command parser owns. `list --kind` and `list --service` go through the same closed vocabulary as addresses before any Security.framework call. Numeric `meta` values are stored and re-emitted digit-exact (`json.Number`), so `9007199254740993` survives `init --meta-json`, `meta set --json-value`, `describe`, `list` and `rotate` unchanged. A raw OSStatus never appears alone: `os_status` is attached and the message names it (`errSecMissingEntitlement`, `errSecAuthFailed`, ...).

Model rules the tool enforces (`STORY-260915-3r0ys5_key-record-model-v2.md`): `service` and `purpose` are `[a-z0-9-]{1,40}`; `algorithm` is `ec-p256` (`ec-p384`/`rsa-3072` are reserved and refused, `ed25519` is refused explicitly, `aes-256-gcm`/`opaque` belong to kind `secret`; nothing is mapped to another algorithm); `usages` is a subset of `sign, verify, wrap, encrypt, decrypt, attest`; `format` keys are validated per kind (a key carries `public` and `signature`, never `envelope`); `extraction` is `none` unless `--extraction human|agent` is typed literally (it is persisted in the record; the split export ACL and `export-private` land with T7, so in this revision every key stays non-extractable at the keychain level and `describe` shows the recorded policy honestly as policy, not capability); `--generate` is refused for a key; only kind `key` is created in this revision (`public-key`, `certificate`, `secret` are validated and refused as `unsupported_kind`). `describe`, `list --json` and `pub --json` derive `operations` from a primitive registry — one row today, `(key, ec-p256, keychain)` — filtered by `usages`, `validity.not_after` and `extraction`; a record with no registry row reports `operations: []`, `exposure: unknown` and the `unsupported_primitive` finding instead of a guess. Items written by the first revision (`mac-keyvault/1 store=... created=...` tags) are reported as `schema: 1` with `service`/`purpose`/`kind`/`algorithm` `unknown`; they are never upgraded and `rotate`/`meta set` refuse them with `metadata_unknown`. The persisted record tag obeys the same single-document rule as `--meta-json`: a schema-2 record followed by a second JSON document, token or garbage is an unreadable record (`describe` reports the problem, `rotate` refuses with `metadata_unknown` and creates nothing, the old item is left untouched); only whitespace around the one document is tolerated. The same decoder is strict about members: a persisted record carrying a JSON field the schema-2 struct does not define — at the top level or inside `format`, `origin`, `issuer`, `validity` — is an unreadable record too (`record_unreadable` finding; `rotate` and `meta set|unset` refuse with `metadata_unknown`, zero creates or updates, old tag byte-identical), never a readable record with the field silently erased before the invariant table runs; `meta` stays an open map and accepts any non-reserved name. Every record field has exactly one row in a per-kind invariant table (`internal/keyvault/signerclient/invariants.go`, shared with the signer client and aliased by `internal/keyvault`): `init` runs it before any Security call; `rotate` and `meta set|unset` run it plus label agreement on the stored record and refuse with `metadata_unknown` (zero creates, old tag untouched) when any field is forged — a non-null `issuer` or `validity.not_before` on a key, a null `created`, an `origin.source` that is neither `generated` nor `imported:<sha256>`, a `version` below 1, an extraction policy on public material, a format key of another kind, …; `describe`/`list --json` report the same violation as a `record_invalid:<code>` finding so the item stays visible for `delete`. `validity.not_before` is certificate-derived and always null on a key or secret; only `--not-after` is caller-supplied.

Signing (`sign`, T2) is ECDSA P-256 over a caller-supplied SHA-256 digest: `--digest` takes 64 hex characters or `@FILE` with the 32 raw bytes (a file is never hex-decoded), `--data-file`/`--stdin` make the tool hash the bytes itself and the output says so (`hash: sha256`, `digest`, `digest_source: digest|file|stdin`). The bridge signs with `kSecKeyAlgorithmECDSASignatureDigestX962SHA256`, so the digest is signed as given and the private key never leaves Security.framework; the DER corecrypto returns is parsed strictly, normalised to low-S (`normalized: true` in the output when s was in the high half) and re-checked under the record's own public key before it is emitted. Output is strict DER (`ecdsa-der-low-s`, the record's `format.signature` default) or 64-byte `r||s` (`--raw` / `--format ecdsa-raw`); `--out FILE` writes the bytes `0600`, text mode prints hex. Gates run in this order, every one before the keychain is touched: digest length (`invalid_digest`, exit 3), address inside the namespace (`foreign_label`), a readable and invariant-valid record (`metadata_unknown` — a rev1 tag or a forged field never reaches the private key), a registry row (`unsupported_primitive`, exit 1), `usages ∋ sign` (`usage_refused`, exit 3, the hint names the record's usages), `validity.not_after` unexpired (`expired`, exit 3, the hint names the timestamp). `verify` judges a signature over the same digest inputs against a vault address (its readable public half; no usage or validity gate, since verification is always allowed) or any P-256 SPKI file with `--spki` (DER or PEM, no vault access): exit 0 `verified: true`; exit 1 `signature_invalid` with `verified: false` for a well-formed signature that does not match (tampered bytes, another digest, another key); exit 3 `invalid_signature` for a signature that is not strict DER (non-minimal integer or length, trailing bytes, r or s outside `[1, n-1]`) or not exactly 64 raw bytes; exit 3 `high_s_refused` for a valid signature whose s is in the high half unless `--allow-high-s` is typed (the verdict is then computed and `low_s: false` reported); like the strict-DER check, the high-S refusal is judged on the signature bytes alone and happens before the `--spki` file is read or the vault is listed, so a malleable signature never causes a Security call. Signatures made here verify with Go `crypto/ecdsa` and `openssl dgst -sha256 -verify`, and signatures made by both verify here (an openssl signature may need `--allow-high-s`; openssl does not normalise). `describe` now lists `ecdsa-sha256-sign` via `sign` and `ecdsa-sha256-verify` via `verify`; ECDH, ECIES and `export-private` stay `reserved`.

Signer contract for kvctl (`signer serve`, T3): `mac-keyvault signer serve --address <service>/<purpose> [--kind key] [--version N]` binds one vault key and speaks **contract 1** as JSON lines on stdin/stdout, so a consumer such as kvctl's `macos-keychain` backend gets signatures without linking Security.framework or ever seeing the private half. The first stdout line is the hello, `{"contract":1,"ok":true,"result":{tool, tool_version, address, kind, version, label, fingerprint, ops}}` — `version` is the generation the server resolved (the newest at that moment when `--version` was omitted, never 0) and that generation stays bound for the whole stream: a `rotate` after the hello does not move the session, so the hello `fingerprint` attests every later `pub`/`sign`/`verify`/`describe` (a new generation needs a new session); when the address does not resolve, the flags are wrong or the vault cannot be opened, the only line is `{"contract":1,"ok":false,"error":{code, message, hint, os_status?}}` and the process exits with the CLI code — `usage` 2; `foreign_label`, `invalid_service`, `invalid_purpose` (also a negative `--version`), `invalid_kind` 3; `not_found`, `security`, `missing_entitlement`, `failure` 1 — never text on stderr, never the multi-line CLI envelope. Every following stdin line is one request `{"id": <string|number>, "op": "describe"|"pub"|"sign"|"verify", ...}` and gets exactly one response line in order: `{"id", "ok": true, "result"}` or `{"id", "ok": false, "error": {code, message, hint, os_status?}}`. `describe` returns the record view (`describe --json`'s result); `pub` takes `format: spki-der` (default, `result.der_base64`) or `spki-pem` (`result.pem`); `sign` takes `digest` (64 hex, SHA-256) and `format: ecdsa-der-low-s|ecdsa-raw` (default the record's `format.signature`) and returns `{label, fingerprint, hash, digest, format, signature (hex), signature_base64, low_s, normalized}`; `verify` takes `digest`, `signature` (hex), `format` (default DER) and `allow_high_s` and returns `{..., verified}` — a false verdict is `ok: false` with `error.code: signature_invalid` **and** `result.verified: false`. The stream never ends on a bad request: a line that is not one JSON object is `bad_request` under `id: null`, a member the op does not take is `bad_request` under the request's id — judged on presence, before the value is read, so an explicit `"allow_high_s": false` on `describe`/`pub`/`sign` or a `"signature": ""` on `pub` is refused exactly like an undefined member (`describe` takes no member besides `id`/`op`; `pub` takes `format`; `sign` takes `format`, `digest`; `verify` takes `format`, `digest`, `signature`, `allow_high_s`), as is a member of the wrong JSON type or a malformed value, a missing/null/non-scalar id is `missing_id`, an op outside the four is `unknown_op`, and the vault's own gates answer with their contract codes (`invalid_digest`, `invalid_signature`, `high_s_refused`, `usage_refused`, `expired`, `metadata_unknown`, `unsupported_primitive`, `not_found` when the key vanished after the hello, `security` with `os_status`). Blank lines are skipped; EOF on stdin exits 0. Every operation runs the same gates as the CLI command of the same name — the contract adds no path around `usages`, `validity`, the trust gate or the prefix guard, and the address is parsed by the same `ParseAddress`, so a raw label is refused before the vault is opened. The wire is pinned byte for byte by golden fixtures in `internal/keyvault/testdata/signer-v1/*.json` (one file per request/response, loaded by `internal/keyvault/signertest`): ten key sessions served through `SignerServer.Serve` — `signer`, `verify-only`, `expired`, `unreadable`, `no-row`, `no-spki`, `corrupt`, `bad-spki`, `entitlement`, `backend-failure` — four startup-failure hellos (`missing`, `hello-security`, `hello-entitlement`, `hello-failure`), and the `startup` session driven through the CLI entry point `run()` by `cmd/mac-keyvault` (`TestRunSignerServeStartupGolden`: args, exit code and the one hello line for `usage`, `foreign_label`, `invalid_service`, `invalid_purpose`, `invalid_kind`, `failure`); `go test ./internal/keyvault -run TestSignerServeGoldenWire -update` and `go test ./cmd/mac-keyvault -run TestRunSignerServeStartupGolden -update` regenerate them — review the diff. The error contract is one registry, `signerclient.ErrorContract` (`internal/keyvault/signerclient/codes.go`, 39 codes with their exit class; every `keyvault.Code*` constant is an alias of it and the CLI classifier takes the exit class from it); the closed set a stream can carry is its `Stream` rows, read through `signerclient.StreamErrorCodes()` — 21 codes: `bad_request`, `missing_id`, `unknown_op`, `usage`, `foreign_label`, `invalid_service`, `invalid_purpose`, `invalid_kind`, `not_found`, `failure`, `security`, `missing_entitlement`, `invalid_digest`, `invalid_signature`, `high_s_refused`, `signature_invalid`, `invalid_public_key`, `usage_refused`, `expired`, `metadata_unknown`, `unsupported_primitive`. Three tests keep that set honest from different sides: `TestSignerGoldenCoversStreamErrorCodes` enumerates the corpus against the registry in both directions (21 of 21 codes have a byte-exact golden negative, no fixture carries an undeclared code), `TestSignerStreamCodesEmittedByProduction` provokes every declared code through `run(signer serve …)` and requires the emitted code to be declared and golden-covered (driver set = declared set), and `TestErrorContractRegistryComplete` parses `codes.go` with `go/parser` so a `Code*` constant without a row or a row without a constant fails. `internal/keyvault/signerclient` is the stdlib-only Go client kvctl vendors: `Start(ctx, Options{Binary, Address, Kind, Version})` spawns the server and refuses any contract but 1 (`ErrContract`) and any hello that is not the one binding it asked for — `tool` must be `mac-keyvault`, `address` the requested address, `kind` the requested kind (`key` when omitted), `version` pinned (never 0) and, when one was requested, that one, `label` and `fingerprint` present, `ops` exactly `describe,pub,sign,verify` — with `ErrProtocol` and the process killed (`TestStartRefusesHelloBoundToAnotherIdentity`, one row per member); the client also enforces the closed error surface it documents, judging every hello and response envelope as one shape before it reads `ok` (`checkEnvelope`): only `{ok: true, result}` with no `error` member and `{ok: false, error}` with a `Stream` code of `ErrorContract` are admitted, plus `{ok: false, result, error}` for `verify` alone (the documented false verdict); an `error` member next to `ok: true`, a missing or `null` result on `ok: true`, no error object on `ok: false`, a result next to any other op's refusal, or an `error.code` outside the `Stream` rows on either side of `ok` is `ErrProtocol`, the server is killed and every later call fails, while a declared refusal is a typed `*Error` after which the session stays usable (`TestClientFailsClosedOnUndeclaredErrorCode`, `TestClientRefusesMalformedEnvelopeBeforeReadingOK` — 13 shapes × hello/pub/verify); that shape judgement is made on the raw line, not on a lossy typed decode: `decodeEnvelope` (`internal/keyvault/signerclient/envelope.go`) reads every hello and response as `map[string]json.RawMessage` first and enforces member presence and JSON type — `ok` present and boolean, `id` present/non-null/scalar on a response and absent on the hello, `contract` absent on a response, `result` a non-null object when present, `error` a non-null object with exactly `code`/`message`/`hint` as present non-null strings plus an optional numeric `os_status`, no other member at either level — before the typed `Response` is built, so an absent or `null` `ok`, `error: null`, `result: null` next to a refusal, or an error object missing `message`/`hint` is `ErrProtocol` instead of decoding to `false`/absent/`""` (`TestClientRefusesEnvelopeMissingOrNullMembers` — 47 raw JSON rows written verbatim by the fake server, 86 of 86 applicable hello/call entries driven, 4 admitted controls); that raw read is not a Go map either: every contract-bearing object on both ends — the client's envelope, its nested `error`, the hello result and every op result, and the server's request line — is read by one token-level reader, `signerclient.DecodeObject` (`object.go`: `json.Decoder.Token` in source order, a second member of one DECODED name refused — `"contract":2,"co\u006etract":1` included, since the decoder resolves the escape before the comparison — exactly one object, nothing after it), because a map decode keeps the last of two repeated members and a gate that runs after it never sees the contradiction — and that reader is not the gate for a nested object either: `encoding/json` collapses a repeat inside `format`, `origin`, `validity`, `meta` or an `operations[i]` entry before any per-object check runs, so the one owner is `signerclient.CheckDocument` (`object.go`), a recursive `json.Decoder.Token` walk over the WHOLE document at every depth (objects in objects, objects in arrays, first and later elements) that refuses a repeated decoded member name anywhere (naming it and its path, `duplicate member "public" at format`) and anything but exactly one document, and it runs before any typed decode from both entry points — `DecodeObject` (client hello/response lines, server request lines) and `DecodeSingleJSON` (the persisted record tag, `--meta-json`, `meta set --json-value`) (`TestClientRefusesDuplicateMembers`, 29 rows with the contradictory value first, 38 of 38 hello/call entries, nine of them nested in the `describe` result; `TestCheckDocument`; server side `TestSignerServeRefusesDuplicateMembers` and goldens `signer-36..43`: `bad_request` under `id: null` naming the duplicate; tag side `TestDecodeRecordRefusesNestedDuplicateMembers`; input side `TestRunMetaJSONRejectsTrailingDocument`); and every result is JUDGED before a typed helper returns it — `checkResult` (`result.go`) is the one owner, run inside `Call`, that binds the result to the pending request (`hash` `sha256`, `digest` and effective `format` as sent, `high_s_allowed` as sent) and to the accepted hello (`label`, `fingerprint`, and through the fingerprint the public key: a `pub` result must parse as a P-256 SPKI whose `Fingerprint` is the hello's; a `sign` result must be low-S in the announced format with `signature_base64` the same bytes and must verify with `crypto/ecdsa` under that key; a `verify` verdict is re-derived under that key and must agree member by member, and only `signature_invalid` and `high_s_refused` may — and must — carry one), with required members present and non-null and no undefined member; any mismatch is `ErrProtocol`, the server killed, the client unusable (`TestClientRefusesResultNotBoundToRequestOrHello`, 135 rows through the typed helpers against a fake that owns a real key). A `describe` result is judged with the vault's own record model, not a projection: the schema-2 `Record`, its vocabulary, `DecodeSingleJSON` and the per-kind invariant table live in `signerclient` (`record.go`, `invariants.go`; `keyvault` aliases them), `Describe` returns a typed `signerclient.Description`, and `checkDescribe` decodes the result closed (wrong JSON type, `null`, or an undefined member at any level is `ErrProtocol`), requires `schema: 2`, binds `kind`/`version`/`service`/`purpose`/`label`/`fingerprint` to the hello and the label to the one the record derives, runs `ValidateStored` and requires `findings` to report exactly the `record_invalid:<code>` the table raises (in both directions), keeps `exposure` to `never|process|unknown` with `unknown` iff `unsupported_primitive` (then no `operations`), and refuses findings outside the read vocabulary, repeated findings and `validity_expired` on a record without `not_after`. The attested key is fetched once per session through the same `pub` gate before the first `sign`/`verify`. `Fingerprint`, `ParseSignature`, `IsLowS`, `ParseSPKI` and `DecodeObject` are exported so a consumer judges the same way; `Describe`, `PublicKey`, `PublicKeyPEM`, `Sign`, `Verify`, `Call`, `Close` (exit 0 on EOF), and `CryptoSigner` adapts the key to `crypto.Signer` (SHA-256 only, DER out) so `x509.CreateCertificate` signs through the vault; a foreign id, an unparsable line or an early EOF is `ErrProtocol` and the client refuses further calls. The client suite drives the built binary end to end against a test-label key (rotating it between the hello and the first request to prove the session stays on the attested generation) and verifies with `crypto/ecdsa` and a self-signed X.509 certificate. Stated bound: kvctl is not code yet (bsim `EPIC-260915-3slg4l`), so mac-keyvault defines the contract and this client is the only consumer it is proven against; no live kvctl interop exists.

Duplicate refusal is atomic across processes: `init`, `rotate` and `meta set` hold an exclusive `flock` on `~/Library/Application Support/mac-infra/keyvault/init.lock` across one listing and the create, because the legacy keychain itself accepts duplicate labels.

Store decision (recorded on `EPIC-260915-1g0e1c_secure-enclave-probe.md` and re-verified while building the tool): an ad-hoc signed CLI gets `-34018 errSecMissingEntitlement` for a permanent Secure Enclave key, for any `kSecAttrAccessControl`-based ACL (it routes the item into the Data Protection keychain), and for `kSecAccessControlUserPresence`. `--enclave` and `--user-presence` therefore try the real Security call and fail with `missing_entitlement`; there is no silent keychain fallback. Persisting Secure Enclave keys needs a signed helper with a provisioning profile and is a separate follow-up. The Security.framework bridge is a small cgo C file (`internal/keyvault/security_darwin.c`): the `security` CLI cannot express `SecKey` ACLs or the Enclave shape, and a separate Swift helper would add a second binary to sign and trust in the ACL.

Two legacy-keychain traps the bridge works around, both proven by tests: `kSecAttrIsExtractable=false` and `kSecAttrAccess` are honoured only at the top level of the `SecKeyCreateRandomKey` attributes (inside `kSecPrivateKeyAttrs` they are silently ignored, which made the first revision's keys exportable), and `SecItemUpdate` on a legacy key writes `kSecAttrApplicationTag` into the label attribute, so the record is updated through `SecKeychainItemModifyAttributesAndData`. The suite proves that `SecKeyCopyExternalRepresentation` and `SecItemExport` both fail with `-25316 errSecDataNotAvailable` for the private half and that the installed ACL trusts exactly the calling binary for sign/decrypt/derive/export. A rebuilt `mac-keyvault` still lists, exports, rotates, and deletes keys without a prompt, but private-key use from a different binary is subject to the keychain's own authorization prompt. Tests use only service `test` (labels `works.relux.mac-keyvault.<kind>.test.*`) and delete them in cleanup; a guard wrapper fails the suite before any other label reaches the keychain.

## Guarded Browser Session Workflows

Both browser tools operate through Apple Events without focusing a browser in
their normal paths. JavaScript automation must be enabled manually; the tools
never toggle browser preferences with UI scripting:

- Safari: `Develop -> Allow JavaScript from Apple Events`
- Chrome: `View -> Developer -> Allow JavaScript from Apple Events`

The targeting asymmetry is load-bearing. Chrome exposes stable window and tab
ids, so `mac-chrome-session` pins every operation to the exact pair. Safari has
stable window ids but no tab ids; `mac-safari-session` therefore acts on the
current tab of one exact window. A Safari tab switch is target drift, so
`--origin` is mandatory for `run-js`, `snapshot`, and `fetch-file`. The atomic
page-context origin check refuses before the payload runs.

```bash
# Chrome: exact tab, background by default
mac-chrome-session list
mac-chrome-session run-js \
  --window-id 704793720 \
  --tab-id 704793726 \
  --origin https://example.com \
  --script 'document.readyState' \
  --out .temp/mac-chrome-session/result.txt

# Safari: exact window, current tab, mandatory origin
mac-safari-session run-js \
  --window-id 55138 \
  --origin https://example.com \
  --script 'document.readyState'
```

Chrome permits `run-js` without `--origin` for exceptional bounded reads, but
prints `guard: unguarded` so the result cannot be mistaken for a guarded call.
Safari does not permit that exception. Chrome `focus`, `trusted-input`, and
`upload` are the only commands allowed to activate or raise Chrome, and all
require exact window/tab/origin guards plus `--human-authorized`. Safari `focus` likewise
requires an explicitly requested visible handoff. `close`/`close-window` also
require an exact target and should be used only for agent-owned state or an
explicit user request.

Chrome `run-js` accepts exactly one of `--script` or `--file`. Optional
`--out PATH` preflights a private temporary file in the destination directory,
then atomically publishes the page result with mode `0600`; stdout reports only
the artifact path and never duplicates page content. Missing, blank, invalid,
or unwritable output paths fail without falling back to stdout.

For an explicitly authorized visible Chrome handoff, use the IDs and origin
from `list` rather than a tab position:

```bash
mac-chrome-session focus \
  --window-id 704793720 \
  --tab-id 704793726 \
  --origin https://example.com \
  --human-authorized
```

The focus path re-enumerates fresh Chrome window/tab arrays, selects only the
unique matching IDs, verifies the origin before and after selection, moves that
exact Chrome window to index 1, activates Chrome, then verifies that the same
window is frontmost and the same tab is active. It never finds a window by
title or falls back to whichever window/tab was already frontmost.
Missing/duplicate targets, origin drift, unreadable attestation, or failed
post-focus verification refuse the operation.

Use `trusted-input` only when the user explicitly authorizes visible text entry
and, optionally, one named autocomplete choice. The versioned JSON request is
bounded and read from stdin so field and option values do not enter argv or
normal logs:

```bash
printf '%s\n' \
  '{"version":1,"inputSelector":"input[type=search]","text":"non-secret test text","optionSelector":"[role=option]","optionText":"Named option","timeoutMs":5000}' |
  mac-chrome-session trusted-input \
    --window-id 704793720 \
    --tab-id 704793726 \
    --origin https://example.com \
    --human-authorized \
    --request-stdin
```

The command first completes the same exact-target focus verification. It then
admits exactly one visible editable text/search input, temporarily marks it
with an unguessable Accessibility description, focuses that exact native
element, sets the bounded value and caret semantically, then posts only a fixed
non-secret append/Backspace pair while Chrome is active, the exact window is
the unique native main window, and the nonce element stays focused. The nonce
correlates the native element back to the exact tab without title matching.
Success requires a trusted DOM `input` event and an exact value match. Optional
selection admits at most 20 visible
matches, requires one normalized exact-text option, presses its nonce-marked
native element, and requires a trusted click plus the selected input value.
Selectors are capped at 512 bytes, text at 512 characters/2048 bytes, option
text at 256 characters/1024 bytes, and the deadline at 10 seconds. Output is
only version, origin, and `ok`/`typed`/`selected` booleans; field values are not
printed or persisted. Any target/origin/element drift fails closed.

All explicit visible paths require Chrome JavaScript from Apple Events.
`trusted-input` and `upload` also require macOS Accessibility access for the installed, signed
`mac-chrome-session` identity. Grant that executable access in System Settings
-> Privacy & Security -> Accessibility when macOS requests it; do not automate
the consent UI.

Use `upload` only after the user explicitly authorizes the visible native file
chooser interaction. The request is a bounded JSON object on private stdin so
absolute source paths never enter argv or normal logs:

```bash
printf '%s\n' \
  '{"version":1,"inputSelector":"input[type=file]","paths":["/private/task/evidence.pdf","/private/task/order.doc"],"allowedExtensions":[".pdf",".doc"],"maxFileBytes":33554432,"maxTotalBytes":67108864,"timeoutMs":15000}' |
  mac-chrome-session upload \
    --window-id 123456 \
    --tab-id 123457 \
    --origin https://example.com \
    --human-authorized \
    --request-stdin
```

The command validates one to eight clean absolute paths as regular non-symlink
files, enforces explicit extension and byte ceilings under fixed 32 MiB
per-file and 64 MiB total hard limits, and rejects duplicate basenames. It
copies only those files into a mode-`0700` temporary directory with mode-`0600`
entries, then focuses only the exact guarded Chrome target. A cryptographic DOM
nonce identifies one visible enabled file input in Chrome's Accessibility tree.
The native bridge first requires a successfully read zero-sheet state, presses
that element, retains the one resulting file-chooser sheet by exact AX identity,
navigates to the otherwise-empty staging directory, selects all staged entries,
and retains the same identity through the close wait without coordinates or
`System Events`. Only proven empty/same-chooser snapshots are retryable; an
Accessibility read error, null/wrong-type value, ambiguity, or replacement
refuses immediately instead of being treated as chooser absence. Staging is
removed on exit.
Multi-file requests require the DOM input's `multiple` property.

When the input declares `accept`, upload validates it during preparation,
immediately before native interaction, and again before success attestation.
The bounded contract admits at most 512 characters and 32 unique
comma-separated tokens: dot extensions up to 16 characters, exact MIME types,
and the standard `image/*`, `audio/*`, or `video/*` wildcards. Every staged
filename must match a declared extension or its fixed known MIME mapping;
unsupported tokens, unknown MIME evidence, and mismatches fail closed. The
visibility gate walks at most 64 element ancestors, rejects hidden/ARIA-hidden,
collapsed, zero-opacity, non-default filter or mask, non-displayed, or
non-targetable ancestry, and requires the exact input to win a bounded viewport
hit test. The type, enabled, visibility, hit-test, `multiple`, and `accept`
decisions are rebound to the same nonce-bearing input at every upload phase.

Success requires a trusted DOM `change` event and an exact browser-observed
filename, size, and count match after the chooser closes. Target/origin drift,
ambiguous or hidden inputs, chooser ambiguity, unsupported extensions, changed
files, unsupported or mismatched DOM acceptance, untrusted events, metadata
mismatch, and timeouts fail closed. Stdout
contains only version, guarded origin, accepted basenames, and count; it never
contains file bytes or absolute paths. This intentionally brings Chrome
forward and requires Accessibility permission, so it is not a silent primitive.

For protected Chrome files, use the sealed `fetch-file` command instead of
clicking download links. It performs each start, poll, and chunk read against
the same exact window/tab and canonical HTTPS origin, so it neither focuses
Chrome nor enters Chrome's native multiple-download flow:

```bash
printf '%s' '{"version":1,"resource":"/api/private/document.pdf","maxBytes":26214400,"timeoutMs":90000}' \
  | mac-chrome-session fetch-file \
      --window-id 704793720 \
      --tab-id 704793726 \
      --origin https://example.com \
      --out .temp/BUG-000000-example/document.pdf \
      --request-stdin
```

The protected resource is supplied only through that bounded versioned stdin
envelope; `mac-chrome-session` declares no `--resource` flag and refuses one if
passed. This is the outer privacy boundary: a command line is durable agent
session and tool evidence and an interactive shell may persist it in history, so
a document or sticky identifier must never reach argv. The envelope is a single
JSON object of at most 8192 bytes accepting only `version` (must be `1`),
`resource` (at most 4096 bytes), `maxBytes`, and `timeoutMs`; unknown fields,
trailing JSON, and out-of-range bounds are refused before any browser call and
no refusal echoes the envelope.

The resource must resolve to the guarded HTTPS origin and may not contain user
info or a fragment; cross-origin and redirecting requests fail closed. The
tool-authored page request uses browser-owned same-origin credentials without
reading or returning cookies, authorization headers, or browser storage. The
resource URL is carried to Apple Events over private stdin and is never emitted
in stdout, stderr, or response metadata.

That promise is structural, not a rule applied per failure site. Every
`fetch-file` failure — invocation, request envelope, validation, output
preflight, transfer, and output publication alike — is collapsed into one closed
internal diagnostic type (`chromectl.FetchFileDiagnostic`) that holds a single
private enum code and nothing else: no wrapped error, no path, no origin, no
child text. A fixed code selects a fixed literal, and one emitter in
`mac-chrome-session` performs the only failure print on this path. Failure
output is therefore always exactly one line, `fetch-file: <fixed message>`, and
never a formatted error. Exit status is `2` for a refused invocation or an
unverifiable request envelope and `1` for every other failure.

The closed vocabulary is: invocation refused; request could not be verified;
request refused; browser target is no longer available; browser target origin
changed; page-context transport unavailable; page-context transport failed;
page-context response could not be verified; another sealed fetch is already
running; size limit; timeout; non-success HTTP status; redirect refused;
page-context fetch failed; private output could not be prepared; private output
could not be published; and a catch-all safe failure. An error that reaches the
boundary without a recognized classification collapses to that catch-all instead
of being rendered, so a missed conversion fails closed rather than becoming the
next leak.

Everything below that boundary is a classification input only. The stdin program
handed to `osascript` embeds the resource, so a failing child could otherwise
quote it back through its own stderr or stdout; sealed page-context calls
discard both child streams and produce a fixed Go-chosen kind
(`child-exit-status`, `child-unavailable`, `page-context-execute-failed`,
`unverifiable-response`) that selects a code and is then dropped — those kinds
are no longer printed for `fetch-file`. Target loss keeps its own classification
because the JXA program returns a sentinel-sealed `window-missing` /
`tab-missing` envelope instead of throwing, and the page-context `catch` arm
drops the caught error whole because a JXA execution error can quote the program
it failed on.

The nested browser-session guard envelope is authenticated by shape, not by
provenance, so a sealed child can mint a well-formed `origin-mismatch` response
whose `origin` field is a copy of the resource-bearing program it received. That
observed value is dropped at the transport and cannot be reconstructed at the
boundary. `errors.Is` against `browsersession.ErrTargetMissing` and
`ErrOriginMismatch` still classifies correctly for Go callers, while `errors.As`
to the detail-bearing `TargetMissingError` / `OriginMismatchError` types fails by
construction. Output preflight and atomic-publish failures are treated the same
way: the underlying filesystem error names the explicit output path, so only the
fixed code crosses. Expect no page source, URL, query name, query value, output
path, or syscall text in any `fetch-file` failure output, whatever the child or
the filesystem returns.

`timeoutMs` is bounded in integer milliseconds before it becomes a
`time.Duration`. `time.Duration` is int64 nanoseconds, so comparing after the
conversion let a large millisecond count wrap back into range — `288230376151711754`
became `10ms`. Response streaming is capped in page
context and checked again before publication. Only status, byte count, and a
validated media type leave page context. `--out` is preflighted before browser
execution and published by same-directory atomic rename with mode `0600`; a
target/origin change, timeout, size refusal, decode error, or write error leaves
the prior destination untouched. The hard limits are 100 MiB and five minutes.

The shared JavaScript guard refuses case-insensitive occurrences of
`document.cookie`, `cookieStore`, `localStorage`, `sessionStorage`, `indexedDB`,
`navigator.credentials`, and `openDatabase` on every CLI path that reaches page
context. This blocklist is an accident-prevention speed bump, not a JavaScript
sandbox: constructed property names can bypass substring checks. The actual
tool guarantee is narrower and enforceable: it never intentionally reads,
prints, persists, or transports browser session material, and URLs, fragments,
and response headers leaving the tool are sanitized. URL sanitization is
structural rather than name-based: scheme, host (with any nonstandard port) and
path survive, the entire query string is replaced with `[redacted-query]`, the
fragment with `[redacted]`, user info is dropped, and payload-carrying opaque
URLs (`data:`, `javascript:`, `view-source:`, `mailto:`) become
`[redacted-opaque-url]`. A parameter-name denylist cannot fail closed against an
authenticated site that names its document and sticky identifiers freely, so no
query byte survives `list`. Keep returned page content bounded and store raw
evidence only in task-scoped private (`0600`) artifacts.

### Sealed Slack reads

`slack-read` is the sole exception that may locate Slack Web authorization in
browser storage. It does so only inside compiled, tool-authored JavaScript and
never returns, prints, logs, persists, or places the token in argv or the
environment. Generic `run-js --script` and `--file` continue to refuse
`localStorage`, cookies, authorization data, and the other blocked sources.

The command requires the exact Chrome window/tab, the literal
`https://app.slack.com` origin, and a `T...` workspace id. The origin and
`/client/<workspace-id>` path are checked in the same page evaluation that
locates the selected workspace's supported `localConfig_v2` token and starts
the request. Origin/workspace drift dispatches nothing. Missing or changed
browser storage schema returns `capability-unavailable`; there is no credential
export fallback.

Only these compiled read methods are admitted: `auth.test`,
`conversations.list`, `conversations.info`, `conversations.history`,
`conversations.replies`, `users.list`, and `search.messages`. One versioned
request arrives over bounded stdin; caller JavaScript, writes, unknown
methods/arguments, oversized input/output, deep JSON, and token-shaped input or
output are refused or redacted:

```bash
printf '%s\n' \
  '{"version":1,"method":"conversations.list","args":{"limit":1}}' |
  mac-chrome-session slack-read \
    --window-id 123456 \
    --tab-id 123457 \
    --origin https://app.slack.com \
    --workspace-id T0123456789 \
    --request-stdin
```

Method arguments are typed and closed to unknown fields:

- `conversations.info`: required conversation `channel`; optional
  `include_locale` and `include_num_members` booleans.
- `conversations.history`: required `channel`; optional bounded `cursor`,
  `limit` from 1 through 100, Slack `oldest`/`latest` timestamps, `inclusive`,
  and `include_all_metadata`.
- `conversations.replies`: the history arguments plus a required Slack `ts`.
- `users.list`: optional bounded `cursor`, `limit` from 1 through 100,
  `include_locale`, and `team_id`; when supplied, `team_id` must exactly match
  `--workspace-id`.
- `search.messages`: required query of at most 512 bytes; optional `count` from
  1 through 100, `page` from 1 through 1000, bounded `cursor`, `sort` (`score`
  or `timestamp`), `sort_dir` (`asc` or `desc`), `highlight`, and a matching
  `team_id`.

Conversation ids, Slack timestamps, cursors, queries, and team ids are
validated before Chrome execution. Secret-shaped values, trailing JSON, and
unknown fields are refused. `auth.test` still accepts no arguments, and the
existing bounded `conversations.list` contract is unchanged.

The response is a versioned JSON envelope. It can contain ordinary Slack data.
Xox/xapp, Bearer, and JWT-shaped spans inside response strings and JSON object
keys are replaced in place with `[redacted]` while surrounding non-secret text
and safe keys are preserved. A response is refused when key redaction would
make two object keys collide, so sanitization never overwrites a value. Compact
JWT/JWE-like spans extend through every contiguous dot-delimited token segment,
favoring fail-closed redaction over returning a possible token tail. Keep live
evidence to booleans/counts with a bounded projection and never
persist channel, user, or message content unless the task explicitly requires a
private artifact.

Safari agent-created background windows are closed automatically by
`snapshot --url` and `fetch-file --page`; otherwise close the exact id returned
by `open-bg`. Authenticated fetches remain in Safari page context with
`credentials: "include"`. Screenshots remain out of scope because they require
Screen Recording permission.

### Agent-facing site facade

Use `mac-browser-site` when an agent needs structured repeated-item reads,
cache-only full-text search, or one declared page mutation. The adapter JSON
pins a Chrome exact window/tab or Safari exact window, a mandatory origin, the
existing deterministic extraction template, a bounded pagination contract,
and an allowlist of mutation selectors. Query syntax follows the separate
`q`/`grep`/`m` contract:

```bash
mac-browser-site q --adapter .temp/browser/marketplace.json --format compact \
  'schema(); list(skip=0,take=20,max_pages=3,where_field=title,where_value=lamp) { id title price }'

mac-browser-site grep --adapter .temp/browser/marketplace.json \
  --format compact --file query-0123456789abcdef.jsonl -i 'lamp'

mac-browser-site m --adapter .temp/browser/marketplace.json --format compact \
  --dry-run 'invoke(name=install)'
mac-browser-site m --adapter .temp/browser/marketplace.json --format compact \
  --confirm 'invoke(name=install)'
```

`q` supports semicolon-separated batches, field projection, the extractor's
`equals`/`contains`/`prefix` predicate, and a hard 100-item result / 1,000-item
scan bound. `next-page`, page-owned `cursor`, and `infinite-scroll` adapters are
bounded by `maxPages <= 20`; cursor values stay inside the site's own click
handler and never enter output, command arguments, URLs, or cache. `grep` never
opens a browser and searches only canonical validated JSONL records inside a
descriptor-rooted site cache; every facade-owned path component is checked
before the physical root is opened, and symlinked components are refused. An
explicit `grep --file` naming a final symlink fails with
`CACHE_SCOPE_REFUSED`; it is never reported as an empty search result. `m`
prevalidates the whole batch and dispatches no
page action without both an adapter-declared mutation and `--confirm`;
`--dry-run` is a no-write preview.

`hasMore` is tri-state evidence: `true` requires an observed record beyond the
requested window, `false` requires either the complete `none` page or an
explicit adapter `advanced:false`, and `unknown` covers duplicate/stale pages,
caller or adapter page bounds, and the global scan bound. Partial or malformed
extract/advance envelopes are typed failures rather than false exhaustion.

Adapter origins containing credentials, paths, query strings, or fragments are
refused. Public field names and returned records are checked for cookie,
storage, credential, authorization, token, and opaque session-state shapes;
one canonical outbound boundary classifies every schema/list/cache/grep/error
and compact/JSON render as `clean`, `redacted`, `refused`, or `unknown`.
Bearer/JWT and recognized opaque credential families—including GitHub,
GitLab, `sk-proj-*`, `sk-*`, and Stripe-style `sk_*` forms—are refused. This is
a fail-closed scanner for named/recognizable secret shapes; ambiguous long
opaque credential candidates report `SENSITIVE_RESPONSE_UNKNOWN` rather than
being declared public. It is not a claim that every arbitrary string can be
semantically identified as a token. One normalized name policy covers fields,
JSON keys, assignments, and URL query names, including cookie, local/session
storage, session id/state, authorization, credential, key, and token families.
HTTP(S)
schemes, hosts, decoded query names, and query values are parsed
case-insensitively. The decoded hostname and every bounded-decoded path
component pass that same name policy plus recognized/opaque credential
classification before the URL is released. Every duplicate sensitive query
value, user info, and fragment is redacted. A secret-bearing query name or
nested/repeatedly encoded secret URL is refused. A bounded normalization queue covers literal,
percent-encoded, nested, JSON-escaped, backslash-escaped, and case-varied
representations, then rescans transformed output to a fixed point. Malformed or
ambiguous URL/JSON input fails closed as
`SENSITIVE_RESPONSE_UNKNOWN`. Extractor, pagination-advance, and mutation
evidence—and adapter JSON metadata—are duplicate-key and scalar checked before
lossy decoding. Browser transport stdout/stderr is never used as public error
detail; failures expose only a stable typed kind and generic message. Cache grep never
re-emits source JSONL bytes: it rejects duplicate keys and renders only a
canonical re-encoding of the exact validated record. See the
[site facade reference](agents/skills/mac-infra/references/browser-site-facade.md)
for the adapter schema and pagination semantics.

Successful `list` calls depersonalize the complete projected result through
`internal/docsanitize` before cache persistence or public rendering. Recognized
names, email addresses, phone numbers, addresses, birth dates, passport/SNILS/tax
identifiers, payment cards, and IP addresses become stable category placeholders
within that result; field names, record order, and ordinary values stay intact.
Ambiguous public fields such as product `name`, `addressType`, and application or
organization `author` are changed only when their values contain recognizable PII.
`grep` accepts only cache records that are already depersonalized and refuses raw
PII or malformed records instead of repairing them during a read. The independent
secret scanner still runs first and refuses the entire operation without partial
stdout or cache bytes; an unsafe or lossy depersonalization result likewise fails
closed.

### Named persistent heartbeats

Both browser CLIs use the same Go heartbeat manager and managed namespace.
Use `mac-chrome-session heartbeat` for Chrome and
`mac-safari-session heartbeat` for Safari. Every heartbeat has a validated
name, exact target, required origin, interval of at least `15s`, private log,
state file, and one LaunchAgent. Chrome uses an exact window/tab pair; Safari
uses an exact window plus its current tab and the mandatory origin guard.

```bash
mac-chrome-session heartbeat start \
  --name example-chrome \
  --browser chrome \
  --window-id 704793720 \
  --tab-id 704793726 \
  --origin https://example.com \
  --interval 45s \
  --ttl 8h

mac-safari-session heartbeat start \
  --name example-safari \
  --window-id 55138 \
  --origin https://example.com \
  --interval 45s \
  --deadline 2026-08-26T06:00:00Z

mac-chrome-session heartbeat status --name example-chrome
mac-chrome-session heartbeat list
mac-chrome-session heartbeat restart --name example-chrome --ttl 8h
mac-chrome-session heartbeat stop --name example-chrome
mac-safari-session heartbeat status --name example-safari
mac-safari-session heartbeat list
mac-safari-session heartbeat stop --name example-safari
```

`start` performs a live guarded preflight before installing anything, then
waits for the first bounded outcome from the installed background process. A
failed background preflight is booted out and its managed artifacts are
removed instead of reporting a false successful start. Every start requires
exactly one future `--ttl` or RFC3339 `--deadline`. Every LaunchAgent runs the
same signed installed launcher at
`~/Library/Application Support/mac-infra/browser-session/bin/mac-browser-heartbeat-launcher`;
setup atomically updates that path instead of creating a new background-item
identity for every build. Multiple names run concurrently. Origin drift dispatches no
synthetic input, logs only `refused` plus the observed origin, and appears as
`drifted`; missing targets appear as `target-missing`. Other states are
`not-configured`, `configured-not-loaded`, `running`, `unavailable`, `expired`,
`migration-required`, or `unknown` when launchd state cannot be read safely.
Status/list expose `deadline`, `expired`, and `migrationRequired`. Logs contain only timestamp,
outcome, origin, and ready state—never page title or body text.

The first heartbeat through the stable launcher may require macOS Automation
consent for Chrome and Safari. Setup applies the complete ad-hoc designated
requirement `works.relux.mac-infra.browser-session` to that shared heartbeat
launcher; direct Safari CLI actions retain `works.relux.mac-infra.safari-session`. A raw Go linker
signature does not provide an actionable TCC identity. Handle the system prompt
manually; the tool never clicks it or brings a browser forward. Until a bounded
heartbeat outcome exists, `status` reports `unavailable` rather than guessing
that a loaded LaunchAgent can reach page context.

Every scheduled check is limited to three 10-second attempts with short bounded
delays; this deadline does not grow with the heartbeat interval. Status also
validates outcome freshness, so a loaded process with an expired last success
reports `unavailable` and `errorKind: stale-outcome` instead of a false
`running` state.

At the configured deadline, both the runtime and a later `status`/`list` call
remove the managed state, plist, and private log before booting out the job; the
expiry path performs no browser probe and never focuses a browser. Legacy
content-addressed or deadline-free state reports `migration-required`. Restart
it safely with `heartbeat restart --name NAME --ttl DURATION` (or
`--deadline RFC3339`): the replacement target is preflighted before the old job
is stopped, then the old pinned copy is garbage-collected.

`scripts/deinit.sh` stops all managed browser heartbeats and removes the stable
launcher plus legacy pinned copies before deleting the installed CLI, so no respawn-failing
LaunchAgent is stranded. See the detailed
[Chrome](agents/skills/mac-infra/references/chrome-session.md) and
[Safari](agents/skills/mac-infra/references/safari-session.md) references.
