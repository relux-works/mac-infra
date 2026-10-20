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
```

Prep builds the digest-pinned Java 17 image and warms the dedicated Gradle cache
with `--refresh-dependencies TASK --dry-run`, then the task itself on the default
container bridge network. A warm test failure is reported without failing prep;
bootstrap or dependency warm-up failures still fail. Run requires a prep record
matching the canonical repo and current toolchain Dockerfile hash. It executes
the recorded immutable image with `--network none` and `./gradlew --offline TASK`.
Gradle daemon IPC on loopback stays available inside the container.

Each invocation uses the `netnone` Colima profile (VZ, Docker runtime, 4 CPUs,
8 GiB memory, 40 GiB disk; override with `--cpus`, `--memory`, `--disk`). It mounts
only the source read-only and the output writable, disables profile activation,
SSH config generation and port forwarding, and refuses an already running profile.
An invocation that starts the VM stops it even on errors or cancellation. An
explicit `stop` also stops an already running profile. Stop failure is a failure.

The test container drops all capabilities, uses `no-new-privileges`, UID/GID
10001, a read-only root filesystem and bounded tmpfs mounts. Both prep and run
use a HOME tmpfs owned by 10001:10001 with mode 0700 and a 64 MiB limit.
`netnone-gradle-home` mounts at `/gradle`, also set as `GRADLE_USER_HOME`.
The test container has no network interface except loopback, no Docker socket
and no database sidecar. It copies
the repo into a fresh work volume. It excludes `.gradle` directories at every
depth and `build` directories only when their parent contains `build.gradle`,
`build.gradle.kts`, `settings.gradle` or `settings.gradle.kts`. Source packages,
resources and files named `build` are preserved. It always attempts to copy all `build/test-results` and
`build/reports` trees to `--out/<UTC timestamp>/`, retaining relative paths.
The new timestamp directory is writable by the container UID; permissions of the
existing output root are preserved. Keep the output root private if reports are
sensitive. Nonzero test exits produce CLI exit 1; usage errors are 2 and refusals
are 3.

For additional build tools, pass `--toolchain-dockerfile /absolute/Dockerfile`
to both prep and run. Its first FROM, after ordinary comments/blank lines/ARGs,
must use this exact base:

```dockerfile
FROM eclipse-temurin:17-jdk@sha256:fe947d993c32dd9cf651a4353a6ed723c2370b3a9d034ea4cab4775404ea531a
```

Every FROM must use that exact base or reference an earlier stage declared as
`FROM <pinned-base> AS <name>`. Only pinned-base declarations may use AS;
flags such as `--platform`, numeric/forward/unknown stage references, and parser
directives (`# syntax=`, `# check=`, `# escape=`, ignoring case and optional
spaces) before the first instruction are refused. Backslash line continuations
are supported. `COPY --from=<external image>` and `RUN --mount=from=<image>`
can pull content that this tool does not pin. Pinning those images, like
`sdkmanager` packages and other toolchain downloads, is the caller's responsibility.

The file must create or keep user `netnone` with UID/GID 10001 and keep
`/work` and `/gradle` owned by 10001:10001. Docker copies the image mountpoint
ownership into empty named volumes; no root chown container is run. The embedded
base is always built first as `netnone-base:local`; the caller Dockerfile is then
built unchanged from its own directory with no injected build arguments. Its
FROM instructions retain the checked pinned bases or stage references. Prep
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
`docker-config/` and atomically written `prep-records.json`. Docker and Colima use
the dedicated socket and private Docker config; shared contexts/configs stay
unchanged. `status` reads profile status, records, state path and lock ownership.

Selftest retains its fixture/results under the state root. It checks networked
DNS/TCP probes, denied probes, an offline test pass beside a network-exception
test failure, and read-only before/after snapshots of shared Docker contexts,
config hashes, socket identity and other Colima profiles. Its verdict table
requires every row to pass. A concurrent status change to another Colima
profile makes the snapshot row red; rerun selftest after that change settles.
The fixture includes a JUnit test that must compile and use a source package
named `build`, guarding source-copy exclusions. Unit checks use only a fake runner:
`go test -race ./internal/netnone/ ./cmd/mac-netnone/`.
