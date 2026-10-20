package netnone

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const copySource = `set -eu
cd /src
find . -type d \( -name .gradle -o -name build \) -exec sh -c '
 for d do
  if [ "${d##*/}" = .gradle ] ||
     [ -f "$d/../build.gradle" ] || [ -f "$d/../build.gradle.kts" ] ||
     [ -f "$d/../settings.gradle" ] || [ -f "$d/../settings.gradle.kts" ]; then
   printf "%s\n" "$d"
  fi
 done
' sh {} + > /tmp/netnone-excludes
tar --no-wildcards --anchored -X /tmp/netnone-excludes -cf - . | (cd /work && tar --no-same-owner -xf -)
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
printf 'netnone-prep-test-exit=%s\n' "$rc"
exit 0
`
const runScript = copySource + `set +e
./gradlew --offline "$1"
rc=$?
set -e
mkdir -p "/out/$2"
find . -type d \( -path '*/build/test-results' -o -path '*/build/reports' \) -prune -exec sh -c '
 stamp=$1; shift
 for d do
  parent=$(dirname "$d")
  mkdir -p "/out/$stamp/$parent" || exit 1
  cp -R "$d" "/out/$stamp/$parent/" || exit 1
 done
' sh "$2" {} + || exit 125
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
	if err = os.WriteFile(filepath.Join(dir, "Dockerfile"), data, 0600); err != nil {
		return "", Result{}, err
	}
	build, err := s.docker(ctx, "build", "--quiet", "-t", "netnone-base:local", "-f", filepath.Join(dir, "Dockerfile"), dir)
	if err != nil {
		return "", build, err
	}
	image := strings.TrimSpace(string(build.Stdout))
	if !imageID.MatchString(image) {
		return "", build, errors.New("invalid base image id from docker build --quiet")
	}
	if id.Path != "" {
		build, err = s.docker(ctx, "build", "--quiet", "-f", id.Path, filepath.Dir(id.Path))
		if err != nil {
			return "", build, err
		}
		image = strings.TrimSpace(string(build.Stdout))
		if !imageID.MatchString(image) {
			return "", build, errors.New("invalid toolchain image id from docker build --quiet")
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
	args := []string{"run", "--rm", "-i", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "10001:10001", "--tmpfs", "/home/netnone:rw,size=64m,uid=10001,gid=10001,mode=0700", "-v", "netnone-gradle-home:/gradle", "-v", "netnone-work:/work", "-v", o.Repo + ":/src:ro", "-e", "GRADLE_USER_HOME=/gradle", "-w", "/work", image, "sh", "-c", script, "netnone-prep", o.Task}
	res, err := s.e.Runner.Run(ctx, Command{Name: "docker", Args: args, Env: s.env, Stdin: strings.NewReader(string(probe))})
	fmt.Fprintf(s.e.Out, "prep (networked):\n%s%s", res.Stdout, res.Stderr)
	if _, err = checked(res, err); err != nil {
		return "", res, err
	}
	// Warm task failures are informational; bootstrap/dry-run/runner failures are
	// operational failures. The script emits this marker only after the task ran.
	marker := regexpPrepExit(string(res.Stdout))
	if marker < 0 {
		return "", res, errors.New("prep did not report the warm test task exit")
	}
	fmt.Fprintf(s.e.Out, "prep warm task exit=%d (test failure does not fail prep)\n", marker)
	path := id.Path
	if path == "" {
		path = "base"
	}
	err = s.save(Record{o.Repo, o.Task, path, id.SHA, image, s.e.Now().UTC()})
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
func (s *session) deniedArgs(o Options, image string) []string {
	return []string{"run", "--rm", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "10001:10001", "--read-only", "--tmpfs", "/tmp:rw,exec,size=2g", "--tmpfs", "/home/netnone:rw,size=64m,uid=10001,gid=10001,mode=0700", "-v", "netnone-gradle-home:/gradle", "-v", "netnone-work:/work", "-v", o.Repo + ":/src:ro", "-v", o.Out + ":/out", "-e", "GRADLE_USER_HOME=/gradle", "-w", "/work", image}
}
func (s *session) runTests(ctx context.Context, o Options, image string) (string, error) {
	inspected, err := s.call(ctx, "docker", "image", "inspect", image)
	if err != nil {
		return "", err
	}
	if inspected.ExitCode != 0 {
		return "", fail(3, "refused: prepared image is unavailable; run mac-netnone prep first")
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
	args := append(s.deniedArgs(o, image), "sh", "-c", runScript, "netnone-run", o.Task, stamp)
	r, err := s.call(ctx, "docker", args...)
	fmt.Fprintf(s.e.Out, "%s%s\nout: %s\n", r.Stdout, r.Stderr, filepath.Join(o.Out, stamp))
	if err != nil {
		return stamp, err
	}
	if r.ExitCode != 0 {
		return stamp, fail(1, fmt.Sprintf("test task failed (container exit %d)", r.ExitCode))
	}
	return stamp, nil
}
