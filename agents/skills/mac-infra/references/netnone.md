# Network-denied JVM tests (`mac-netnone`)

`mac-netnone` is installed by `./scripts/setup.sh`. Colima and Docker CLIs
must be installed separately.
Source and output paths must be absolute existing directories, without `:` or
`,`; symlinks are resolved. Source files must be readable by container UID 10001.

```bash
mac-netnone prep --repo /absolute/repo --task test
mac-netnone run --repo /absolute/repo --task test --out /absolute/results
mac-netnone selftest
mac-netnone status
mac-netnone stop

# For x86_64-only native tools (for example, Android AAPT2):
mac-netnone prep --arch amd64 --repo /absolute/repo --task test
mac-netnone run --arch amd64 --repo /absolute/repo --task test --out /absolute/results
mac-netnone selftest --arch amd64
```

Prep builds the digest-pinned Java 17 image and warms the dedicated Gradle cache
with `--refresh-dependencies TASK --dry-run`, then the task itself on the default
container bridge network. A failed warm task is tolerated only if at least one
`build/test-results/**/*.xml` exists in `/work` afterward. A failure without test
results, including dependency/bootstrap failure after a successful dry-run, fails
prep and writes no successful prep record. Run requires a prep record
matching the canonical repo, current toolchain Dockerfile hash and architecture.
Legacy records without an `arch` field are treated as arm64; they do not
authorize amd64 runs. `status` shows the architecture of each prep record. Run executes
the recorded immutable image with `--network none` and `./gradlew --offline TASK`.
Gradle daemon IPC on loopback stays available inside the container.

`prep`, `run` and `selftest` accept `--arch arm64|amd64`, defaulting to `arm64`.
Other values are usage errors (exit 2). Use `--arch amd64` for both prep and run
when native tools are available only for linux/amd64, such as AAPT2. It uses VZ
Rosetta and is slower than native arm64; the first amd64 prep pulls the amd64
base image. Every Docker build and container run explicitly selects
`--platform linux/<arch>`, including prep and the denied probe.

The VM remains aarch64 with `--vm-type vz`. Every start explicitly passes
`--vz-rosetta` for amd64 or `--vz-rosetta=false` for arm64, so saved Rosetta
settings cannot carry into an arm64 run. Architecture selection keeps the
existing isolation and shared-state snapshot contract.

Each invocation uses the `netnone` profile in the private Colima home
`~/.colima-netnone` (VZ, Docker runtime, 4 CPUs,
8 GiB memory, 40 GiB disk; override with `--cpus`, `--memory`, `--disk`). It mounts
the source read-only and output writable into the VM, disables profile activation,
updates to `~/.ssh/config`, and port forwarding, and refuses an already running
private profile. Only mac-netnone may use `~/.colima-netnone`; its flock and private
namespace prevent competing starts inside the tool. Every operational Colima and
Docker call explicitly sets `COLIMA_HOME=$HOME/.colima-netnone`,
`LIMA_HOME=$COLIMA_HOME/_lima`,
`DOCKER_HOST=unix://$HOME/.colima-netnone/netnone/docker.sock` and a private
`DOCKER_CONFIG`, replacing inherited roots, `DOCKER_*` and `COLIMA_PROFILE`.
Colima may regenerate its SSH config inside that private home. The short home
path avoids the much longer Application Support path for Lima Unix sockets.

Cleanup is registered before startup: even failed or cancelled startup attempts
stop the profile and report the result. INT, TERM and HUP trigger cancellation.
SIGKILL or a crash can leave the VM running; `mac-netnone stop` recovers it.
Explicit `stop` is administrative and bypasses the run lock and ownership check.
Stop failure fails the invocation. Status/admission use the named row in
`colima list --json`: Running is refused, Stopped or a missing row permits start;
unknown status, malformed data or any list error fails closed.

The test container drops all capabilities, uses `no-new-privileges`, UID/GID
10001, a read-only root filesystem and bounded tmpfs mounts. Both prep and run
use a HOME tmpfs owned by 10001:10001 with mode 0700 and a 64 MiB limit.
`netnone-gradle-home` mounts at `/gradle`, also set as `GRADLE_USER_HOME`.
The test container has no network interface except loopback and no database
sidecar. The tool does not explicitly bind Docker or SSH sockets; arbitrary
source contents are not screened. It copies
the repo into a fresh work volume. It excludes `.gradle` directories at every
depth and `build` directories only when their parent contains `build.gradle`,
`build.gradle.kts`, `settings.gradle` or `settings.gradle.kts`. Source packages,
resources and files named `build` are preserved. Excluded directory paths with
newlines are refused clearly. Both arm64 and amd64 use `cp -R -P -p` to copy
source, then remove the excluded directories; copy and removal failures each
stop execution. GNU tar 1.35 extraction fails with ENOSYS under Linux Rosetta,
so amd64 also copies build outputs before removing them. This is slower for
repos with large `build/` trees; clean those build trees for speed.
It always attempts to copy all `build/test-results` and
`build/reports` trees to `--out/<UTC timestamp>/`, retaining relative paths.
Only the current timestamp directory is bound as `/out`; earlier runs are never
mounted in the container. It is writable by UID 10001 during collection, then
restricted to 0755 (directories) and 0644 (files), including after a failed task.
The cleanup never follows a symlink: it opens every entry with `O_NOFOLLOW`
relative to its parent directory, so a link planted by the test is skipped.
The walk stops 64 directory levels below the run directory; deeper contents
keep their modes and are reported.
The host user owns results through virtiofs. Permission failures are reported
without failing the run. The existing output root and previous runs retain their
permissions. Keep the output root private if reports are sensitive. Nonzero test exits produce CLI exit 1; usage errors are 2 and
refusals are 3.

For additional build tools, pass `--toolchain-dockerfile /absolute/Dockerfile`
to both prep and run. Its first FROM, after ordinary comments/blank lines/ARGs,
must use this exact index base or the per-arch manifest matching `--arch`:

```dockerfile
FROM eclipse-temurin:17-jdk@sha256:fe947d993c32dd9cf651a4353a6ed723c2370b3a9d034ea4cab4775404ea531a
```

The embedded base substitutes the matching manifest into its owned Dockerfile
bytes before building via stdin. Both manifests belong to the pinned index above:

| Architecture | Manifest base |
| --- | --- |
| amd64 | `eclipse-temurin:17-jdk@sha256:fc1394dc03c3de483ea03b14ccf0a076f772f7782aaeffc9d5a2cbde2ae5df0e` |
| arm64 | `eclipse-temurin:17-jdk@sha256:c4378bc2c608f8ca536dc9a60a017a2d675501c55b00b2ac3db9b6a8200a3458` |

Every caller FROM must use that exact index or the matching manifest, or reference
an earlier stage declared as
`FROM <pinned-base> AS <name>`. Only pinned-base declarations may use AS.
The other architecture's manifest and tag-only bases are refused (exit 2).
Before building, mac-netnone rewrites every occurrence of the index in the
caller's validated Dockerfile to the manifest matching `--arch`. The classic
image store can otherwise resolve the index to the other architecture's local
image, and a later step (for example COPY after USER) fails with "does not
provide the specified platform". The selftest builds through such a
toolchain fixture (index FROM, USER root, COPY) on both architectures.
A reference to the index that is split by a line continuation inside the
image name is refused (exit 2): write each reference on one line.
Flags such as `--platform`, numeric/forward/unknown stage references, and parser
directives (`# syntax=`, `# check=`, `# escape=`, ignoring case and optional
spaces) before the first instruction are refused. Logical instructions
containing `<<` (including heredocs, also when `<<` is split by a line
continuation) are refused until the validator supports their bodies.
Backslash line continuations
are supported. `COPY --from=<external image>` and `RUN --mount=from=<image>`
can pull content that this tool does not pin. Pinning those images, like
`sdkmanager` packages and other toolchain downloads, is the caller's responsibility.

The file must create or keep user `netnone` with UID/GID 10001 and keep
`/work` and `/gradle` owned by 10001:10001. Docker copies the image mountpoint
ownership into empty named volumes; no root chown container is run. The embedded
base is always built first as `netnone-base:<arch>`; the caller Dockerfile is then
built from the validated bytes, with the pinned index rewritten to the
per-arch manifest, via `docker build -f - <context dir>`, with
its own directory as context and no injected build arguments. The embedded base
also uses Dockerfile stdin. After every base/toolchain build, the tool inspects
`{{.Os}}/{{.Architecture}}` on the immutable image ID and requires `linux/<arch>`.
Run repeats that assertion after startup, before the test container. A mismatch
refuses with exit 3, writes no new prep record, and still stops the owned VM.
Per-arch manifests and ID assertions avoid ambiguous index inspection with the
classic image store, which may retain only one architecture per reference.
Runtime entrypoints are explicitly `/bin/sh` for
prep/run scripts and `java` for the selftest probe. Toolchain FROM instructions
retain the checked pinned bases or stage references. Prep
uses UID/GID 10001 with all capabilities dropped and `no-new-privileges`, on the
default network. It needs network access for builds and
dependency downloads. A changed Dockerfile or missing image requires prep again.

For Robolectric, fetch the required `android-all` artifacts during prep. Configure
the Gradle test JVM with `-Drobolectric.offline=true` and
`-Drobolectric.dependency.dir=...`, pointing inside the Gradle cache or the copied
repo. In-process databases (SQLite/Room under Robolectric, H2) need no special
setup and start empty in the fresh work volume. There is no `--db-image` option.

Before any profile operation, prep/run/selftest refuse when the host's 5-minute
load exceeds `--max-load` (default: host CPU count). Equality is allowed. A
nonblocking flock prevents overlapping invocations. The private `0700` state
root is `~/Library/Application Support/mac-infra/netnone/`, containing `run.lock`,
`docker-config/` and atomically written `prep-records.json`, keyed by
(repo, toolchain SHA, arch). Docker and Colima use
the private-home socket and private Docker config. Shared-state snapshots detect
endpoint drift; equal snapshots do not prove the absence of intermediate writes.
`status` reads profile status, records, state path and lock ownership.

Selftest retains its fixture/results under the state root. Its `prep arch` and
`run arch` rows each require the JVM `os.arch` plus the little-endian ELF
`e_machine` from bytes 18–19 of `/proc/self/exe`, the executing JVM launcher:
`arch=amd64` with `elf=62`, or `arch=aarch64` with `elf=183`. Missing,
duplicate or mismatched architecture evidence fails the row. It checks networked
DNS/TCP probes, denied probes, and the complete expected JUnit testcase set:
`OfflineTest.arithmetic` and `OfflineTest.buildPackageWasCopied` must pass;
`NetworkTest.repositoryReachable` must fail with an actual UnknownHostException,
NoRouteToHostException, or SocketException with "Network is unreachable".
The failure type (or, when there is none, the exception header on the first
non-empty line of the failure text) decides;
an assertion merely mentioning a network exception cannot qualify. The denied
TCP probe accepts only "Network is unreachable" or NoRouteToHostException;
connection refused is not evidence of network denial. After cleanup, a fresh
private-profile list must confirm stopped state in the lifecycle verdict row.

Read-only before/after snapshots include each Docker context's inspection hash
(using the user's environment), config hashes including default
`~/.colima/ssh_config`, default socket identity, other profile statuses and every
non-netnone default-home `~/.colima/<profile>/colima.yaml` hash. The private home
is excluded from shared-state comparison. Its verdict table
requires every row to pass. A concurrent status change to another Colima
profile makes the snapshot row red; rerun selftest after that change settles.
The fixture includes a JUnit test that must compile and use a source package
named `build`, guarding source-copy exclusions. Unit checks use only a fake runner:
`go test -race ./internal/netnone/ ./cmd/mac-netnone/ ./scripts/`. Local shell
fixtures use fake tools and temporary directories; signal controls target only
their own fake-backed helper process. These tests do not qualify a live VM.
