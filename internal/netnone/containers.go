package netnone

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const copySource = `set -eu
cd /src
rm -f /tmp/netnone-copy-error
find . -type d \( -name .gradle -o -name build \) -exec sh -c '
 for d do
  if [ "${d##*/}" = .gradle ] ||
     [ -f "$d/../build.gradle" ] || [ -f "$d/../build.gradle.kts" ] ||
     [ -f "$d/../settings.gradle" ] || [ -f "$d/../settings.gradle.kts" ]; then
   case "$d" in *"
"*) printf error > /tmp/netnone-copy-error; continue ;; esac
   printf "%s\n" "$d"
  fi
 done
' sh {} + > /tmp/netnone-excludes
if [ -f /tmp/netnone-copy-error ]; then
 echo "source copy refused: excluded directory path contains a newline" >&2
 exit 1
fi
# GNU tar 1.35 extraction uses a syscall that fails with ENOSYS under Linux Rosetta.
# Use the same portable copy-then-remove flow for arm64 and amd64.
if ! cp -R -P -p /src/. /work/; then
 echo "source copy failed" >&2
 exit 1
fi
while IFS= read -r p; do
 case "$p" in
  ./?*) ;;
  *) echo "source copy refused: invalid excluded path" >&2; exit 1 ;;
 esac
 # cp -p keeps a read-only (0555) excluded tree read-only; make it owner-
 # writable first or its children cannot be removed. chmod -R follows no
 # symlinks met during traversal (GNU and BSD).
 # find lists an excluded tree before exclusions nested inside it, so an
 # earlier removal may already have taken this path; nothing is left to do.
 if [ ! -e "/work/${p#./}" ] && [ ! -L "/work/${p#./}" ]; then
  continue
 fi
 if ! chmod -R u+w "/work/${p#./}"; then
  echo "source exclusion removal failed" >&2
  exit 1
 fi
 if ! rm -rf -- "/work/${p#./}"; then
  echo "source exclusion removal failed" >&2
  exit 1
 fi
done < /tmp/netnone-excludes
cd /work
`

// Scripts are fixed assets executed inside the container; tasks and timestamps
// are passed positionally, never joined into executable shell text.
const prepScript = copySource + `cat > /tmp/Probe.java
java /tmp/Probe.java || true
./gradlew --refresh-dependencies "$1" --dry-run
set +e
./gradlew "$1"
rc=$?
if [ "$rc" -ne 0 ]; then
 results=$(find . -type f -path '*/build/test-results/*.xml' -print -quit)
 if [ -z "$results" ]; then
  echo "warm task failed before test results; prep refused" >&2
  exit "$rc"
 fi
 printf 'netnone-prep-test-results=yes\n'
fi
printf 'netnone-prep-test-exit=%s\n' "$rc"
exit 0
`
const runScript = copySource + `set +e
./gradlew --offline "$1"
rc=$?
set -e
find . -type d \( -path '*/build/test-results' -o -path '*/build/reports' \) -prune -exec sh -c '
 for d do
  parent=$(dirname "$d")
  mkdir -p "/out/$parent" || exit 1
  cp -R "$d" "/out/$parent/" || exit 1
 done
' sh {} + || exit 125
exit "$rc"
`

func (s *session) resetWork(ctx context.Context) error {
	if _, err := s.docker(ctx, "volume", "rm", "-f", "netnone-work"); err != nil {
		return err
	}
	if _, err := s.docker(ctx, "volume", "create", "netnone-work"); err != nil {
		return err
	}
	// Empty volumes copy up the image mountpoint ownership on first use.
	// /work and /gradle must already belong to UID/GID 10001 in the image.
	return nil
}
func (s *session) prep(ctx context.Context, o Options, id toolchainID, fixture bool) (string, Result, error) {
	// A private context ensures embedded assets never require a file outside the
	// state directory. Caller Dockerfiles retain their own build context.
	dir, err := os.MkdirTemp(s.state, "base-")
	if err != nil {
		return "", Result{}, err
	}
	defer os.RemoveAll(dir)
	data, err := assets.ReadFile("assets/Dockerfile")
	if err != nil {
		return "", Result{}, err
	}
	data = bytes.Replace(data, []byte("FROM "+BaseImage+"\n"), []byte("FROM "+baseImage(o.Arch)+"\n"), 1)
	// The embedded base must build from the per-arch pin; a template that no
	// longer starts with the index pin would otherwise build from the index.
	if !bytes.HasPrefix(data, []byte("FROM "+baseImage(o.Arch)+"\n")) {
		return "", Result{}, fmt.Errorf("embedded base Dockerfile does not start FROM %s", baseImage(o.Arch))
	}
	build, err := checked(s.e.Runner.Run(ctx, Command{Name: "docker", Args: []string{"build", "--platform", "linux/" + o.Arch, "--quiet", "-t", "netnone-base:" + o.Arch, "-f", "-", dir}, Env: s.env, Stdin: bytes.NewReader(data)}))
	if err != nil {
		return "", build, err
	}
	image := strings.TrimSpace(string(build.Stdout))
	if !imageID.MatchString(image) {
		return "", build, errors.New("invalid base image id from docker build --quiet")
	}
	if err = s.assertArch(ctx, image, o.Arch); err != nil {
		return "", build, err
	}
	if id.Path != "" {
		build, err = checked(s.e.Runner.Run(ctx, Command{Name: "docker", Args: []string{"build", "--platform", "linux/" + o.Arch, "--quiet", "-f", "-", filepath.Dir(id.Path)}, Env: s.env, Stdin: bytes.NewReader(pinToolchain(id.Data, o.Arch))}))
		if err != nil {
			return "", build, err
		}
		image = strings.TrimSpace(string(build.Stdout))
		if !imageID.MatchString(image) {
			return "", build, errors.New("invalid toolchain image id from docker build --quiet")
		}
		if err = s.assertArch(ctx, image, o.Arch); err != nil {
			return "", build, err
		}
	}
	if _, err = s.docker(ctx, "volume", "create", "netnone-gradle-home"); err != nil {
		return "", Result{}, err
	}
	if err = s.resetWork(ctx); err != nil {
		return "", Result{}, err
	}
	probe, _ := assets.ReadFile("assets/Probe.java")
	script := prepScript
	if fixture {
		script = strings.Replace(script, "java /tmp/Probe.java", "java /src/Probe.java", 1)
	}
	// HOME tmpfs needs explicit ownership: Docker defaults to root-owned 0750.
	args := []string{"run", "--platform", "linux/" + o.Arch, "--rm", "-i", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "10001:10001", "--tmpfs", "/home/netnone:rw,size=64m,uid=10001,gid=10001,mode=0700", "-v", "netnone-gradle-home:/gradle", "-v", "netnone-work:/work", "-v", o.Repo + ":/src:ro", "-e", "GRADLE_USER_HOME=/gradle", "-w", "/work", "--entrypoint", "/bin/sh", image, "-c", script, "netnone-prep", o.Task}
	res, err := s.e.Runner.Run(ctx, Command{Name: "docker", Args: args, Env: s.env, Stdin: strings.NewReader(string(probe))})
	fmt.Fprintf(s.e.Out, "prep (networked):\n%s%s", res.Stdout, res.Stderr)
	if _, err = checked(res, err); err != nil {
		return "", res, err
	}
	// Warm failures require test-result evidence; bootstrap/dry-run/runner failures are
	// operational failures. The script emits this marker only after the task ran.
	marker := regexpPrepExit(string(res.Stdout))
	if marker > 0 && !strings.Contains(string(res.Stdout), "netnone-prep-test-results=yes\n") {
		return "", res, errors.New("warm task failed without test results; prep refused")
	}
	if marker < 0 {
		return "", res, errors.New("prep did not report the warm test task exit")
	}
	fmt.Fprintf(s.e.Out, "prep warm task exit=%d (failure tolerated only with test results)\n", marker)
	path := id.Path
	if path == "" {
		path = "base"
	}
	err = s.save(Record{Arch: o.Arch, Repo: o.Repo, Task: o.Task, ToolchainPath: path, ToolchainSHA: id.SHA, Image: image, Time: s.e.Now().UTC()})
	return image, res, err
}
func regexpPrepExit(output string) int {
	for _, line := range strings.Split(output, "\n") {
		if v, ok := strings.CutPrefix(line, "netnone-prep-test-exit="); ok {
			n, err := strconv.Atoi(v)
			if err == nil && n >= 0 && n <= 255 {
				return n
			}
		}
	}
	return -1
}
func (s *session) deniedArgs(o Options, image, entrypoint string) []string {
	args := []string{"run", "--platform", "linux/" + o.Arch, "--rm", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "10001:10001", "--read-only", "--tmpfs", "/tmp:rw,exec,size=2g", "--tmpfs", "/home/netnone:rw,size=64m,uid=10001,gid=10001,mode=0700", "-v", "netnone-gradle-home:/gradle", "-v", "netnone-work:/work", "-v", o.Repo + ":/src:ro", "-e", "GRADLE_USER_HOME=/gradle", "-w", "/work"}
	if o.Out != "" {
		args = append(args, "-v", o.Out+":/out")
	}
	return append(args, "--entrypoint", entrypoint, image)
}
func (s *session) assertArch(ctx context.Context, image, arch string) error {
	inspected, err := s.call(ctx, "docker", "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", image)
	if err != nil {
		return err
	}
	if inspected.ExitCode != 0 {
		return fail(3, "refused: prepared image is unavailable; run mac-netnone prep first")
	}
	observed := strings.TrimSpace(string(inspected.Stdout))
	if observed != "linux/"+arch {
		return fail(3, fmt.Sprintf("refused: built image is %s, expected linux/%s", observed, arch))
	}
	return nil
}
func (s *session) runTests(ctx context.Context, o Options, image string) (string, error) {
	if err := s.assertArch(ctx, image, o.Arch); err != nil {
		return "", err
	}
	if err := s.resetWork(ctx); err != nil {
		return "", err
	}
	stamp := s.e.Now().UTC().Format("20060102T150405.000000000Z")
	// Only this new output directory is made writable to container UID 10001;
	// never change permissions/ownership of the caller's existing output root.
	dest := filepath.Join(o.Out, stamp)
	if err := os.Mkdir(dest, 0777); err != nil {
		return stamp, err
	}
	if err := os.Chmod(dest, 0777); err != nil {
		return stamp, err
	}
	// The container may still be writing here after a cancellation, so the
	// cleanup never follows a path: every chmod goes through a descriptor opened
	// with O_NOFOLLOW below the directory created above.
	defer restrictOutput(dest, s.e.Err)
	o.Out = dest
	args := append(s.deniedArgs(o, image, "/bin/sh"), "-c", runScript, "netnone-run", o.Task)
	r, err := s.call(ctx, "docker", args...)
	fmt.Fprintf(s.e.Out, "%s%s\nout: %s\n", r.Stdout, r.Stderr, dest)
	if err != nil {
		return stamp, err
	}
	if r.ExitCode != 0 {
		return stamp, fail(1, fmt.Sprintf("test task failed (container exit %d)", r.ExitCode))
	}
	return stamp, nil
}

// outputDepthLimit bounds the cleanup walk: at most this many directory levels
// below root are opened, so descriptors and path bytes stay bounded and a deep
// tree written by a test cannot exhaust the host or delay the VM stop.
const outputDepthLimit = 64

// restrictOutput sets directories to 0755 and regular files to 0644 below
// root. Symlinks and other file types are skipped; a name swapped for a
// symlink between listing and opening fails with ELOOP and is skipped too.
// Directories deeper than outputDepthLimit are left as they are and reported.
func restrictOutput(root string, errOut io.Writer) {
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		fmt.Fprintf(errOut, "output permissions: %s: %v\n", root, err)
		return
	}
	restrictDir(fd, root, 0, errOut)
}

func restrictDir(fd int, path string, depth int, errOut io.Writer) {
	dir := os.NewFile(uintptr(fd), path)
	defer dir.Close()
	if err := unix.Fchmod(fd, 0755); err != nil {
		fmt.Fprintf(errOut, "output permissions: %s: %v\n", path, err)
	}
	if depth >= outputDepthLimit {
		fmt.Fprintf(errOut, "output permissions: %s: deeper than %d levels; contents left unchanged\n", path, outputDepthLimit)
		return
	}
	names, err := dir.Readdirnames(-1)
	if err != nil {
		fmt.Fprintf(errOut, "output permissions: %s: %v\n", path, err)
	}
	for _, name := range names {
		child := filepath.Join(path, name)
		cfd, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			if err != unix.ELOOP {
				fmt.Fprintf(errOut, "output permissions: %s: %v\n", child, err)
			}
			continue
		}
		var st unix.Stat_t
		if err := unix.Fstat(cfd, &st); err != nil {
			fmt.Fprintf(errOut, "output permissions: %s: %v\n", child, err)
			unix.Close(cfd)
			continue
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			restrictDir(cfd, child, depth+1, errOut)
		case unix.S_IFREG:
			if err := unix.Fchmod(cfd, 0644); err != nil {
				fmt.Fprintf(errOut, "output permissions: %s: %v\n", child, err)
			}
			unix.Close(cfd)
		default:
			unix.Close(cfd)
		}
	}
}
