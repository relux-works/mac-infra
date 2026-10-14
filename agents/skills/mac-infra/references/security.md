# Read-only security evidence

Use `mac-security` for bounded local evidence, not a malware-free verdict.
It never runs sudo, changes host settings, installs jobs, or modifies services.

```sh
mac-security scan --json
mkdir -p .temp/security
mac-security baseline --file .temp/security/baseline.json --json
mac-security diff --file .temp/security/baseline.json --json
```

JSON goes to stdout and the summary to stderr. Exit 0 means collection completed,
including findings and incomplete checks; 1 means an operational failure; 2 is
usage. All JSON results have a schema number. Checks record observation bounds,
command paths, exits (null when no process exit was observed), and explicit
`ok`, `partial`, or `unavailable` coverage. No raw stdout/stderr is persisted.

Baseline capture is the only explicit write. It requires an existing parent
without symlinks and creates a new `0600` file, refusing overwrite. Use canonical
paths on macOS: `/private/tmp`, not its `/tmp` symlink, if using that location.
Snapshots contain relative paths, permission modes and SHA-256 fingerprints,
never source contents. Inspect coverage and review the host before treating a
baseline as trusted. Diff flags visible additions/changes but reports deletions
only when both snapshots have complete coverage of the source. Unknown sources
remain unknown. Volatile login-item/profile/system-extension command output is
not hashed into stable drift; these inventory sources explicitly remain partial
until a stable, platform-validated identity projection exists. Current-user
crontab content is fingerprinted only on a successful, nonempty response.

Covered fixed filesystem sources: system/current-user launchd directories,
Apple launchd directories, periodic, cron spool and PrivilegedHelperTools.
Other users, kernel extensions, non-system setuid files, arbitrary SSH Includes,
and excluded `com.bsim.*` entries are outside coverage. SSH reads only the fixed
config and bounded `config.d/*.conf` sources; it reports declarations, not an
individual target's evaluated settings. It inspects authorized_keys presence
without opening those files. Agent key count is read using `ssh-add -l`;
comments and fingerprints are suppressed because comments may contain secrets.

Listeners show visible TCP PID/UID/bind/protocol only, with wildcard and
non-loopback warnings. UDP, complete root process visibility, router mappings
and WAN reachability are not established. Sharing shows explicit launchd
overrides only, not active service state. Protection checks recognize only
known replies; absent preferences and custom/transitional protection responses
stay unknown. An XProtect version does not establish freshness or activation.

IOC checks use a bounded list of incident markers against fixed temporary and
launchd names, fixed shell files, and visible numeric network endpoints. They
do not establish absence of compromise. Add a private JSON array with
`--ioc-file PATH` using objects `{ "id": "local-marker", "target": "tmp-name",
"pattern": ".fixture-*" }`. Targets: `tmp-name`, `launch-name`, `shell-content`,
`network`. Paths/commands cannot be supplied by plugins; reports show rule IDs
and match counts, never matched content or plugin patterns. Default rules remain
active. Root SSH-key content, sudoers, process arguments, nested temporary
payloads and encrypted C2 are explicitly outside this first collector contract.

Limits: 2 MiB per source/command, 10,000 filesystem entries per source, 32
filesystem levels, 128 SSH config entries, four seconds per command, and 45
seconds for a CLI collection. Static symlink parents/leaves are refused;
collection is point-in-time and does not atomically attest parent-directory
identity against concurrent rename by another process. A privileged attacker
can falsify local evidence. Treat permission, output-limit and timeout failures
as missing coverage. Persist JSON under private task-scoped directories.

Build without installing or affecting live daemons:

```sh
go build -o .temp/security/mac-security ./cmd/mac-security
go test -count=1 ./internal/security ./cmd/mac-security
```

For router coverage, see [the read-only discovery design](../../../../docs/security/router-discovery.md).
