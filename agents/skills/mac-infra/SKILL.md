---
name: mac-infra
description: >
  macOS workstation infrastructure tooling for diagnosing and fixing local Mac
  audio crackling, CoreAudio daemon glitches, Simulator audio issues, Apple
  Music distortion, USB DAC output problems, Bluetooth output problems, macOS
  video/display smoothness loss, WindowServer/GPU stutter, Docker/VM slideshow
  symptoms, broad CPU, memory, thermal, and process load, authenticated Safari
  and Google Chrome browser-session inspection/harvesting, privacy-safe document
  intake, PII redaction, fseventsd memory/CPU bloat from slow FSEvents
  consumers or high file-event volume, non-extractable P-256 key pairs in the
  login keychain via mac-keyvault, and related maintenance tasks.
triggers:
  - mac load
  - load profile
  - fseventsd
  - fsevents
  - FSEvents bloat
  - fseventsd memory
  - fseventsd CPU
  - mac slow
  - mac sluggish
  - мак тормозит
  - мак подтормаживает
  - CPU profile
  - memory profile
  - disk profile
  - disk usage
  - disk space
  - storage profile
  - cleanup plan
  - keyvault
  - key vault
  - keychain key
  - secure enclave
  - P-256 key
  - signing key
  - mac cleanup
  - cleanup mac
  - high CPU
  - high memory
  - hot mac
  - overheating mac
  - process load
  - top processes
  - activity monitor
  - Mac is hot
  - mac video
  - macOS video
  - video stutter
  - display stutter
  - WindowServer
  - GPU stutter
  - slideshow
  - Docker slideshow
  - video smoothness
  - плавность видео
  - видео лагает
  - слайдшоу на маке
  - дискретность видео
  - дергается видео
  - WindowServer жрет
  - mac audio
  - macOS audio
  - audio crackle
  - crackling audio
  - distorted audio
  - CoreAudio
  - coreaudiod
  - usbaudiod
  - Apple Music crackle
  - TA-22
  - USB DAC
  - AirPods crackle
  - Simulator audio
  - reset audio
  - clean audio
  - звук трещит
  - трещит звук
  - звук хрипит
  - хрипит звук
  - дребезг
  - дребезжит
  - перезапусти звук
  - почисть звук
  - сбрось аудио
  - аудио на маке
  - кор аудио
  - кореаудио
  - audio sweep
  - frequency sweep
  - hearing test
  - local audio test
  - sine sweep
  - 44 kHz audio
  - sleep prevention
  - prevent Mac sleep
  - disable system sleep
  - pmset disablesleep
  - prevent display sleep
  - disable display sleep
  - caffeinate background activity
  - caffeinate can run in the background
  - prevent screen lock
  - prevent idle lock
  - prevent screen saver
  - частотный тест
  - аудиотест
  - тест слуха
  - свип частоты
  - синус свип
  - 44 кГц
  - запретить сон мака
  - не давать маку спать
  - отключить сон macOS
  - не гасить экран
  - не выключать монитор
  - caffeinate работает в фоне
  - не блокировать экран
  - запретить локскрин
  - что жрет проц
  - жрет процессор
  - жрет память
  - греется мак
  - мак греется
  - профайли нагрузку
  - нагрузка на маке
  - мониторинг компа
  - что жрет диск
  - жрет диск
  - место на диске
  - профайли диск
  - почистить мак
  - чистка мака
  - клинап мака
  - safari automation
  - Safari Apple Events
  - Chrome automation
  - Slack browser read
  - Slack sealed read
  - browser heartbeat
  - Chrome heartbeat
  - Safari heartbeat
  - browser automation
  - browser harvest
  - authenticated browser
  - authenticated Safari
  - Safari cookies
  - reuse browser cookies
  - read browser page
  - harvest browser page
  - document sanitizer
  - sanitize document
  - redact PII
  - PII redaction
  - privacy-safe document
  - clean personal data
  - обезличить документ
  - почистить персональные данные
  - убрать персданные
  - персуха в документе
  - анонимизировать документ
  - сафари
  - браузер
  - автоматизация сафари
  - автоматизация хрома
  - кукисы
  - вычитать браузер
  - потрошить браузер
  - харвестить браузер
---

# mac-infra

Use this skill for macOS local maintenance workflows backed by the `mac-infra`
Go tools.

## Sleep Prevention Workflow

Start with the read-only system-wide status:

```bash
mac-infra-core sleep-prevention status
```

The command reads `SleepDisabled` from `/usr/bin/pmset -g` and reports one
`enabled`, `disabled`, or `unavailable` state with `applies_to: AC,battery`.
`disablesleep` is global; do not infer separate values from AC/battery `sleep`
timers in `pmset -g custom`.

Enable or disable only when the user explicitly requests the mutation:

```bash
mac-infra-core sleep-prevention enable
mac-infra-core sleep-prevention disable
```

- Mutations go through the root daemon and expose only the fixed actions backed
  by `/usr/bin/pmset -a disablesleep 1` and
  `/usr/bin/pmset -a disablesleep 0`.
- The setting persists after the command exits until explicitly changed. It is
  not a process-scoped `caffeinate` assertion.
- The policy covers AC and battery but does not change `sleep` timers, standby,
  `hibernatemode`, or `displaysleep`. The display may still turn off.
- `scripts/setup.sh` updates the user binary and installed skill but does not
  restart an existing privileged daemon. Run `mac-infra-core install` after the
  first setup and after core binary updates before using `enable` or `disable`.

## Separate Display And Idle-Lock Prevention Workflow

Do not collapse system sleep, display sleep, and idle Lock Screen behavior into
one mutation. Inspect and control the independent policies separately:

```bash
mac-infra-core sleep-prevention status
mac-infra-core display-sleep-prevention status
mac-infra-core idle-lock-prevention status
```

When the user explicitly requests that the monitor stay on, use:

```bash
mac-infra-core display-sleep-prevention enable
```

This installs a current-user LaunchAgent that keeps one fixed
`/usr/bin/caffeinate -d` assertion alive. It applies on AC and battery while the
user is logged in, does not rewrite `pmset` timers, and does not need the root
daemon. Disable boots out the assertion and removes the LaunchAgent plist:

```bash
mac-infra-core display-sleep-prevention disable
```

macOS may show an App Background Activity notification saying that
`“caffeinate” can run in the background`. Recognize it as this managed
`works.relux.mac-infra-display-sleep-prevention` LaunchAgent, not an unknown
third-party process. Keep the `caffeinate` name; do not rename or disable it
solely because of the notification. Turning it off in Login Items & Extensions
defeats persistent display-sleep prevention. If ownership is uncertain, verify
the LaunchAgent label, `/usr/bin/caffeinate -d` arguments, and
`PreventUserIdleDisplaySleep` assertion before changing anything.

When the user explicitly requests prevention of automatic idle Lock Screen,
use the current-user command:

```bash
mac-infra-core idle-lock-prevention enable
mac-infra-core idle-lock-prevention disable
```

The command prevents the automatic screen-saver lock trigger by capturing and
restoring the current host's `com.apple.screensaver idleTime` value. Enable both
display sleep and idle-lock prevention to prevent the two idle triggers that
lead to Lock Screen. Status reports that display sleep remains a separate policy.

Never use `sysadminctl -screenLock off` for this workflow. Manual Lock Screen
and the existing password-after-lock policy must remain intact. Idle-lock
disable refuses to invent an `idleTime` restore value when no saved snapshot
exists.

## Audio Frequency Sweep Workflow

For local frequency/hearing/output-chain tests, read
[audio-frequency-sweep.md](references/audio-frequency-sweep.md) before running
the sweep tools. Start with:

```bash
mac-audio-sweep device
mac-audio-sweep tui
```

## Authenticated Browser Session Workflows

Read [Safari](references/safari-session.md) or [Chrome](references/chrome-session.md) before page-context work; those references own the exact `run-js`, output, focus, trusted-input, native upload, download, Slack, permission, and secret-boundary contracts.
Safari is exact-window/current-tab and always requires `--origin`; Chrome is exact-window/exact-tab. Keep either browser in the background unless the user explicitly requests visible handoff. Never export cookies, storage, authorization headers, credentials, or tokens. Start with `mac-safari-session check-js` or `mac-chrome-session list`; the user must manually enable JavaScript from Apple Events.

For a user-authorized Chrome attachment, use `mac-chrome-session upload` with
exact window/tab IDs, mandatory origin, `--human-authorized`, and one bounded
versioned request on private stdin. It admits one visible file input and one to
eight explicit regular files under declared extension/size bounds, requires a
native chooser zero-to-one transition, retains that exact Accessibility sheet
identity through selection and closure, refuses any unreadable or malformed
sheet snapshot instead of retrying it as absence, and checks a bounded declared DOM `accept`
contract plus effective ancestor visibility/hit targeting during preparation,
immediately before native work, and again before success attestation, rejects
non-default ancestor filter or mask effects, and verifies a trusted change plus
exact filename/size/count metadata. Do not
put source paths in argv, use an active-tab fallback, or claim success from the
chooser action alone.

Use `mac-chrome-session heartbeat` or `mac-safari-session heartbeat` for named keepalives in the shared private namespace and stable installed launcher. Every start requires exactly one finite `--ttl` or RFC3339 `--deadline`; `status`/`list` expose deadline and expiry. Migrate legacy deadline-free/content-addressed state with `heartbeat restart --name NAME --ttl DURATION` without focusing either browser.

## Agent-Facing Browser Site Facade

For structured repeated-item reads, cache-scoped search, or guarded site
mutations, read [browser-site-facade.md](references/browser-site-facade.md).
Use `mac-browser-site q|grep|m` with a private task-scoped adapter and retain the
underlying exact-target/origin guard.

## Privacy-Safe Document Intake Workflow

Use this before reading or persisting extracted content when a local or
browser-downloaded document may contain personal data or secrets:

```bash
mac-document-sanitize --json PATH
```

Read only the returned `sanitized_path`. The command keeps raw extracted text in
memory, never changes the source, writes `0600` artifacts, names default outputs
from the source SHA-256 rather than its filename, and reports categories/counts
without storing matched values.

Supported inputs: TXT, Markdown, JSON, XML, YAML, CSV, TSV, HTML, RTF, DOC,
DOCX, PDF, and XLSX. PDF extraction needs `pdftotext` from Homebrew `poppler`.
Export legacy XLS or ODS files as XLSX, CSV, or TSV first.

If automatic heuristics miss a known value, put exact values one-per-line in a
task-scoped `0600` file and rerun:

```bash
mac-document-sanitize --redact-from .temp/mac-document-sanitize/extra.txt PATH
```

Do not claim guaranteed anonymization. Review sanitized output before external
disclosure. Delete only raw files the agent itself created under `.temp/`; never
delete or modify the user's source document.

## Load Profiling Workflow

- For broad CPU, memory, thermal, pressure, and process evidence, start here:

```bash
mac-load-profile capture
```

- For quick terminal triage without writing a full bundle:

```bash
mac-load-profile snapshot --top 20
```

- To inspect one suspicious process or family:

```bash
mac-load-profile inspect sing-box
mac-load-profile inspect 12345
```

- To gather a CPU sample, use it only when profiling needs stack evidence:

```bash
mac-load-profile inspect sing-box --sample 5
```

- Use specific profilers only after the broad profile points there. For tunnel
  issues:

```bash
mac-load-profile tunnel
```

- For Cisco AnyConnect disconnected-state socket filter leaks:

```bash
mac-load-profile anyconnect
mac-load-profile anyconnect --logs
```

- For fseventsd memory or CPU bloat, see the FSEvents Bloat Workflow below:

```bash
mac-load-profile fsevents
```

- `mac-load-profile` is read-only. It must not stop, restart, kill, or mutate
  processes.

## FSEvents Bloat Workflow

Use this when the Mac is sluggish and `fseventsd` shows up with a large RSS
(gigabytes) or sustained CPU in `mac-load-profile snapshot`. fseventsd buffers
events for slow consumers and never releases that memory on its own; it also
burns CPU in proportion to file-event volume. Both were observed together in a
real incident: Colima's `mountInotify` forwarder watched the whole `$HOME` for
a week while git-heavy `go test` loops produced ~130k file operations per
second, and fseventsd grew to 40 GB RSS at 100% CPU.

- Start with the read-only diagnostic. It needs no sudo:

```bash
mac-load-profile fsevents
mac-load-profile fsevents --json
```

It reports fseventsd pid/RSS/CPU against thresholds (warn 256 MB, critical
512 MB, CPU 50%; a healthy fseventsd sits at 10-20 MB), known FSEvents consumers and event generators from a pattern
allowlist (Colima `--inotify` daemon, Spotlight, Time Machine, iCloud Drive,
git fsmonitor, watchman, third-party sync agents, running `go test`), every
`~/.colima/*/colima.yaml` with `mountInotify` and `mounts`, and the size of
`go-build*` leftovers under the temp dir. fseventsd clients cannot be
enumerated without root, so the consumer list is a heuristic, not a client
table.

- Fix the input first. For Colima, set `mountInotify: false` unless a container
  really needs host file events; if it does, list only those directories under
  `mounts:` (an empty `mounts: []` means the whole `$HOME`), then
  `colima restart`. Remove `go-build*` leftovers from finished or killed test
  runs yourself; mac-infra never deletes them.

- Restart fseventsd through the root daemon only when RSS is at or above the
  threshold. The CLI refuses below it; `--force` overrides:

```bash
mac-infra-core fseventsd-restart
mac-infra-core fseventsd-restart --force
```

The daemon action is fixed to `/bin/launchctl kickstart -k
system/com.apple.fseventsd` and reports before/after pid and RSS. It needs
the installed daemon to be updated from a build that includes the action:
run `mac-infra-core install` after `scripts/setup.sh`.

- Keep a watchdog so the next bloat is caught at 512 MB, not 40 GB:

```bash
mac-infra-core fseventsd-watchdog enable
mac-infra-core fseventsd-watchdog enable --threshold-gb 3 --interval 5m
mac-infra-core fseventsd-watchdog enable --auto-restart
mac-infra-core fseventsd-watchdog status
mac-infra-core fseventsd-watchdog disable
```

It installs the current-user LaunchAgent
`works.relux.mac-infra-fseventsd-watchdog`, which runs `mac-infra-core
_fseventsd-check` every 10 minutes by default. Over the threshold it posts a
macOS notification (re-notifies at most once per six intervals while still
over). `--auto-restart` is opt-in and calls the same guarded daemon action;
without it the watchdog only notifies. Settings live in
`~/Library/Application Support/mac-infra/fseventsd-watchdog.json`, not in
the plist. `disable` boots the agent out and removes the plist but keeps the
state file for `status`.

- Never renice, `taskpolicy -b`, suspend, or otherwise throttle fseventsd.
  It drains a kernel ring buffer; a starved daemon drops events and every
  FSEvents client (Spotlight, Time Machine, Finder, iCloud) responds with a
  full volume rescan, which costs far more than the CPU you tried to save.
  Reduce the event volume or the consumer count instead.

## Video Smoothness Workflow

- For subtle slideshow-like video/UI animation stutter, especially when Docker
  or VM work is active, start with read-only video/display triage:

```bash
mac-video-profile snapshot --top 20
```

- For a durable bundle with display/GPU topology, WindowServer/process evidence,
  thermal and memory pressure, power assertions, display registry state, and
  optional recent WindowServer/display/GPU/Metal/frame logs:

```bash
mac-video-profile capture --logs
```

- Capture artifacts are written under `.temp/mac-video-profile/capture-*`.
- `mac-video-profile` is read-only. It must not reset WindowServer, kill apps,
  change refresh rate, change display settings, run privileged `powermetrics`,
  or mutate Docker/VM state.
- Use `mac-load-profile capture` after this only when the evidence points to a
  broader CPU, memory, thermal, disk, network, or process-load issue.

## Disk Space Profiling Workflow

- Use this when the user needs to understand where disk space went:

```bash
mac-disk-profile scan "$HOME" --depth 3 --json .temp/mac-disk-profile/home.json
mac-disk-profile top "$HOME" --limit 30
mac-disk-profile explain "$HOME/Library/Developer"
```

- `mac-disk-profile` is read-only. It must not delete, move, or mutate files.
- Prefer `scan` when a persisted JSON artifact is useful for later analysis.
- Use `explain` for one suspicious path after `scan` or `top` identifies it.

## Key Vault Workflow

- Use `mac-keyvault` when an agent needs a persistent, non-extractable P-256 key pair on this Mac. Every item is a schema-2 record addressed as `<service>/<purpose>` plus `--kind` (default `key`) and `--version N` (default newest); the label `works.relux.mac-keyvault.<kind>.<service>.<purpose>.v<N>` is derived by the vault and never typed:

```bash
mac-keyvault --json init --service kvctl --purpose pki-root --title "test PKI root" --usages sign,verify --meta owner=alexis
mac-keyvault --json list --service kvctl          # records + label, fingerprint, exposure, operations, findings
mac-keyvault --json describe kvctl/pki-root       # newest generation; --version 1 selects one
mac-keyvault pub kvctl/pki-root --out .temp/pki-root.pem   # --format spki-der|spki-pem|jwk
mac-keyvault --json sign kvctl/pki-root --digest "$(shasum -a 256 payload.bin | cut -c1-64)"   # strict DER low-S in result.signature (hex); --raw for r||s; --out FILE writes bytes
mac-keyvault --json sign kvctl/pki-root --data-file payload.bin        # tool hashes with SHA-256; result.hash/digest/digest_source say so
mac-keyvault --json verify kvctl/pki-root --data-file payload.bin --sig @payload.sig   # exit 0 verified; 1 signature_invalid; 3 high_s_refused / invalid_signature
mac-keyvault --json verify --spki pki-root.pem --digest HEX --sig HEX   # any P-256 SPKI DER/PEM, no vault access
mac-keyvault --json meta set kvctl/pki-root ticket MI-7
mac-keyvault --json rotate kvctl/pki-root         # ...v2, record copied, old key kept
mac-keyvault --json delete kvctl/pki-root --confirm --version 1
```

- Read `error.code` and `error.hint` in `--json` mode; every outcome, usage errors included, is a `{ok, command, result|error{code, message, hint, os_status}}` envelope on stdout with an empty stderr. Exit 2 is `usage`, exit 3 is a policy refusal, exit 1 is an operational failure (`not_found`, `missing_entitlement`, `security`).
- Invalid `service`/`purpose`/`kind`/`algorithm`/`usages`/`format`/`extraction`, `--generate` on a key, reserved names inside `meta`, a duplicate `(kind, service, purpose)` and any input that is not a `<service>/<purpose>` address (raw labels included) are refused with exit 3 before Security.framework is called. Do not retry these; fix the input.
- `sign` takes a SHA-256 digest (`--digest` 64 hex or `@FILE` of 32 raw bytes, never hex-decoded) or hashes `--data-file`/`--stdin` itself and reports that; it refuses before any keychain call with `invalid_digest` (wrong length, exit 3), `usage_refused` (record without usage `sign`, exit 3), `expired` (`validity.not_after` passed, exit 3), `metadata_unknown` (rev1 tag or forged record) and `unsupported_primitive` (no registry row, exit 1). Output is strict DER with low-S, or `--raw` 64-byte `r||s`; `normalized: true` means the keychain returned a high-S value that was folded. `verify` returns exit 0 (`verified: true`), exit 1 `signature_invalid` (well-formed but not matching: `verified: false`), exit 3 `invalid_signature` (not strict DER / not 64 raw bytes) or `high_s_refused` (pass `--allow-high-s` only when the signer is known not to normalise, e.g. openssl); both are decided on the signature bytes before the vault or the `--spki` file is touched. An agent verifies foreign signatures with `--spki FILE` (no vault access) and never passes `--allow-high-s` by default.
- `operations` in `describe`/`list --json` is derived from the primitive registry and the record's `usages`/`validity`/`extraction`; `via: sign`/`via: verify` name the commands that perform `ecdsa-sha256-sign`/`ecdsa-sha256-verify`, `via: reserved` means no command performs it yet, and `findings: ["unsupported_primitive"]` means the tool does not know the primitive. Select an operation by its `name`/`input`/`output`, never by guessing from `algorithm`.
- `rotate` refuses a record whose store or schema is unknown (`metadata_unknown`, first-revision tags included) rather than assuming the keychain; delete such items with `--confirm --version N` and recreate them.
- Every record field is checked against a per-kind invariant table on `init`, `rotate` and `meta set|unset` (a forged stored field — non-null `issuer` or `validity.not_before` on a key, null `created`, bad `origin.source`, … — is `metadata_unknown`, nothing created or rewritten); `describe`/`list --json` show the same violation as `findings: ["record_invalid:<code>"]`. Treat that finding as "delete and recreate", never as a record to reproduce.
- A persisted record carrying a JSON member the schema does not define (top-level or inside `format`/`origin`/`issuer`/`validity`) is an unreadable record (`findings: ["record_unreadable"]`); `rotate` and `meta set|unset` refuse it with `metadata_unknown` and write nothing. Only `meta` is an open map; a field that must drive behaviour is added to the schema, never smuggled in and silently dropped.
- `--enclave` and `--user-presence` fail with `missing_entitlement` (`os_status: -34018`) on this ad-hoc signed binary: the Secure Enclave and the Data Protection keychain need a provisioning profile. Do not retry in a loop and do not fall back silently; report the failure.
- `--extraction` defaults to `none`. An agent never passes `--extraction agent` for a key on its own; that value is typed only on an explicit human instruction so the transcript shows the choice. `export-private` and `--human-authorized` are not implemented in this revision; agents never pass `--human-authorized` by contract.
- Tests and probes must use `--service test` (labels `works.relux.mac-keyvault.<kind>.test.*`) and delete them afterwards.

## Cleanup Planning Workflow

- Start with read-only planning only:

```bash
mac-cleanup scan --json
mac-cleanup target --json .temp/mac-cleanup/project-plan.json /path/to/project
mac-cleanup xcode --json
mac-cleanup xcode-runtimes --json
```

- If macOS denies access to protected paths or the scan reports permission
  warnings, do not casually grant Full Disk Access to Terminal, iTerm2, Cursor,
  VS Code, or another broad launcher. Every process launched from that app may
  inherit the access. Prefer partial scans until a dedicated narrow mac-infra
  Full Disk Access runner exists.
- Show the guidance instead:

```bash
mac-cleanup permissions
```

- `mac-cleanup permissions --open` intentionally returns `not implemented`
  until a dedicated narrow Full Disk Access runner exists.

- `mac-cleanup xcode-runtimes` detects unsupported CoreSimulator runtimes that
  Xcode can still list even after their devices are gone. It is dry-run by
  default and deletes only with explicit `--delete`.
- Other `mac-cleanup` flows currently plan cleanup candidates only. They do not
  delete or move files.
- Treat cleanup output as review material. Ask the user before any future apply
  flow removes or trashes files.

```bash
mac-cleanup xcode-runtimes
mac-cleanup xcode-runtimes --delete
```

## Audio Crackle Workflow

- Start with read-only diagnostics:

```bash
mac-audio-reset diagnose
```

- If Apple Music restart does not help and the symptom survives across USB DAC
  and Bluetooth output, inspect for CoreAudio/Simulator involvement:

```bash
mac-audio-reset diagnose --logs
mac-audio-reset reset --dry-run
```

- Do not run the reset unless the user explicitly agrees. It shuts down booted
  iOS simulators and restarts CoreAudio through the privileged helper.
- If the user directly asks to clean/reset/fix Mac audio, treat that as explicit
  agreement and run the reset without another confirmation prompt.

```bash
mac-audio-reset reset
```

- One-time privileged helper setup:

```bash
mac-infra-core request-permissions sudo
mac-infra-core install
mac-infra-core status
```

- Use `mac-infra-core request-permissions sudo` when sudo credentials are
  needed. Do not run ad hoc `sudo` commands from the shell for mac-infra work;
  let the Go CLI own the sudo prompt and permission scope.
- This is separate from Full Disk Access. Do not grant Full Disk Access to
  Terminal, iTerm2, Cursor, VS Code, or another broad launcher.

After installation, `mac-audio-reset reset` should not need interactive `sudo`.

## AnyConnect Socket Filter Cleanup Workflow

- Start with read-only diagnostics:

```bash
mac-load-profile anyconnect
```

- If AnyConnect reports disconnected but `com.cisco.anyconnect.macos.acsockext`
  is still hot or large, inspect the cleanup plan:

```bash
mac-infra-core anyconnect-cleanup
```

- Run cleanup only when the user explicitly asks to kill/clean/reset Cisco
  AnyConnect, or after they approve the dry-run plan:

```bash
mac-infra-core anyconnect-cleanup --apply
```

- The apply path is allowlisted in `mac-infra-core`: it verifies AnyConnect is
  disconnected, terminates the Cisco socket-filter extension process, and
  restarts `com.cisco.anyconnect.vpnagentd` through `launchctl kickstart`.
- Do not use ad hoc `sudo`, broad `killall`, packet capture, traffic blocking,
  or TLS interception for this workflow.

## Operational Notes

- The reset intentionally runs `simctl shutdown all` as the current user before
  calling the root helper. Simulator state is user-scoped.
- The root helper only exposes allowlisted actions; it is not a generic command
  executor.
- If a USB DAC is running at `192000 Hz`, recommend trying `48000 Hz` or
  `96000 Hz` in Audio MIDI Setup when crackle repeats under Apple Music.
- Reboot is the last resort, not the first move.
