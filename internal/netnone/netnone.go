package netnone

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const Profile = "netnone"
const BaseImage = "eclipse-temurin:17-jdk@sha256:fe947d993c32dd9cf651a4353a6ed723c2370b3a9d034ea4cab4775404ea531a"

const BaseImageAMD64 = "eclipse-temurin:17-jdk@sha256:fc1394dc03c3de483ea03b14ccf0a076f772f7782aaeffc9d5a2cbde2ae5df0e"
const BaseImageARM64 = "eclipse-temurin:17-jdk@sha256:c4378bc2c608f8ca536dc9a60a017a2d675501c55b00b2ac3db9b6a8200a3458"

func baseImage(arch string) string {
	if arch == "amd64" {
		return BaseImageAMD64
	}
	return BaseImageARM64
}

//go:embed assets
var assets embed.FS

// Options are literal arguments, never interpolated into a host or guest script.
type Options struct {
	Repo, Task, Out, Toolchain, Arch string
	MaxLoad                          float64
	CPUs, Memory, Disk               int
}

func DefaultOptions() Options { return Options{Arch: "arm64", CPUs: 4, Memory: 8, Disk: 40} }

type Engine struct {
	Runner   Runner
	Now      func() time.Time
	Load     func(context.Context) ([3]float64, error)
	CPUCount func() int
	Home     func() (string, error)
	StateDir func(string) string
	UserEnv  []string
	Out, Err io.Writer
}

func New(r Runner, out, errOut io.Writer) *Engine {
	e := &Engine{Runner: r, Now: time.Now, CPUCount: runtime.NumCPU, Home: os.UserHomeDir, UserEnv: os.Environ(), Out: out, Err: errOut}
	e.StateDir = func(home string) string { return filepath.Join(home, "Library/Application Support/mac-infra/netnone") }
	e.Load = func(ctx context.Context) ([3]float64, error) {
		res, err := r.Run(ctx, Command{Name: "sysctl", Args: []string{"-n", "vm.loadavg"}, Env: e.UserEnv, Timeout: 5 * time.Second})
		if err != nil {
			return [3]float64{}, err
		}
		if res.ExitCode != 0 {
			return [3]float64{}, errors.New("cannot read vm.loadavg")
		}
		return ParseLoad(string(res.Stdout))
	}
	return e
}
func ParseLoad(s string) ([3]float64, error) {
	var values [3]float64
	fields := strings.Fields(strings.NewReplacer("{", " ", "}", " ").Replace(s))
	if len(fields) != 3 {
		return values, errors.New("invalid vm.loadavg")
	}
	for i, v := range fields {
		n, err := strconv.ParseFloat(v, 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 {
			return values, errors.New("invalid vm.loadavg")
		}
		values[i] = n
	}
	return values, nil
}

type failure struct {
	code    int
	message string
}

func (f *failure) Error() string    { return f.message }
func fail(code int, s string) error { return &failure{code, s} }
func (e *Engine) Execute(ctx context.Context, action string, o Options) int {
	err := e.execute(ctx, action, o)
	if err == nil {
		return 0
	}
	fmt.Fprintln(e.Err, err)
	var f *failure
	if errors.As(err, &f) {
		return f.code
	}
	return 1
}
func (e *Engine) execute(ctx context.Context, action string, o Options) error {
	if action != "prep" && action != "run" && action != "selftest" && action != "status" && action != "stop" {
		return fail(2, "unknown command")
	}
	lifecycle := action == "prep" || action == "run" || action == "selftest"
	if lifecycle {
		if o.Arch != "arm64" && o.Arch != "amd64" {
			return fail(2, "--arch must be arm64 or amd64")
		}
		if o.MaxLoad == 0 {
			o.MaxLoad = float64(e.CPUCount())
		}
		if o.MaxLoad <= 0 || math.IsNaN(o.MaxLoad) || math.IsInf(o.MaxLoad, 0) {
			return fail(2, "--max-load must be positive and finite")
		}
		load, err := e.Load(ctx)
		if err != nil {
			return err
		}
		if load[1] > o.MaxLoad {
			return fail(3, fmt.Sprintf("refused: host load 5m=%g above --max-load %g (1m=%g 15m=%g)", load[1], o.MaxLoad, load[0], load[2]))
		}
		if o.CPUs <= 0 || o.Memory <= 0 || o.Disk <= 0 {
			return fail(2, "--cpus, --memory and --disk must be positive integers")
		}
	}
	home, err := e.Home()
	if err != nil {
		return err
	}
	state := e.StateDir(home)
	s := session{e: e, home: home, state: state, env: privateEnv(e.UserEnv, home, state)}
	if action == "status" {
		return s.status(ctx)
	}
	if action == "stop" {
		return s.stop(ctx)
	}
	if err := os.MkdirAll(state, 0700); err != nil {
		return err
	}
	if err := os.Chmod(state, 0700); err != nil {
		return err
	}
	lock, err := acquireLock(state)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := os.MkdirAll(filepath.Join(state, "docker-config"), 0700); err != nil {
		return err
	}
	if action == "selftest" {
		return s.selftest(ctx, o)
	}
	o.Repo, err = directory(o.Repo)
	if err != nil {
		return err
	}
	if o.Task == "" || strings.HasPrefix(o.Task, "-") {
		return fail(2, "--task must be a nonempty Gradle task, not an option")
	}
	identity, err := toolchain(o.Toolchain, o.Arch)
	if err != nil {
		return err
	}
	o.Toolchain = identity.Path
	if action == "run" {
		o.Out, err = directory(o.Out)
		if err != nil {
			return err
		}
		records, err := s.records()
		if err != nil {
			return err
		}
		rec, ok := records[recordKey(o.Repo, identity.SHA, o.Arch)]
		if !ok || rec.Repo != o.Repo || rec.ToolchainSHA != identity.SHA || rec.Arch != o.Arch || !imageID.MatchString(rec.Image) {
			return fail(3, "refused: no prep record for this repo/toolchain/arch="+o.Arch+"; run mac-netnone prep first")
		}
		return s.lifecycle(ctx, o, func() error { _, err := s.runTests(ctx, o, rec.Image); return err })
	}
	scratch, err := os.MkdirTemp(state, "prep-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(scratch)
	o.Out, err = directory(scratch)
	if err != nil {
		return err
	}
	return s.lifecycle(ctx, o, func() error { _, _, err := s.prep(ctx, o, identity, false); return err })
}

type session struct {
	e           *Engine
	home, state string
	env         []string
}

func (s *session) call(ctx context.Context, name string, args ...string) (Result, error) {
	return s.e.Runner.Run(ctx, Command{Name: name, Args: args, Env: s.env})
}
func checked(r Result, err error) (Result, error) {
	if err != nil {
		return r, err
	}
	if r.ExitCode != 0 {
		return r, fmt.Errorf("command failed (exit %d): %s", r.ExitCode, strings.TrimSpace(string(r.Stderr)))
	}
	return r, nil
}
func (s *session) docker(ctx context.Context, args ...string) (Result, error) {
	r, err := s.call(ctx, "docker", args...)
	return checked(r, err)
}
func (s *session) stop(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	r, err := s.call(ctx, "colima", "stop", "--profile", Profile)
	fmt.Fprintf(s.e.Out, "colima stop --profile netnone: exit=%d error=%v %s%s\n", r.ExitCode, err, r.Stdout, r.Stderr)
	_, err = checked(r, err)
	return err
}
func (s *session) lifecycle(ctx context.Context, o Options, work func() error) (err error) {
	status, err := s.profile(ctx)
	if err != nil {
		return err
	}
	if status == "running" {
		return fail(3, "refused: colima profile netnone is already running (not started by this invocation); stop it with mac-netnone stop")
	}
	args := []string{"start", "--profile", Profile, "--activate=false", "--ssh-config=false", "--template=false", "--port-forwarder", "none", "--mount-inotify=false", "--mount-type", "virtiofs", "--mount", o.Repo, "--mount", o.Out + ":w", "--vm-type", "vz", "--runtime", "docker", "--cpus", strconv.Itoa(o.CPUs), "--memory", strconv.Itoa(o.Memory), "--disk", strconv.Itoa(o.Disk)}
	rosetta := "--vz-rosetta=false"
	if o.Arch == "amd64" {
		rosetta = "--vz-rosetta"
	}
	args = append(args, rosetta)
	defer func() {
		stopErr := s.stop(context.Background())
		if stopErr != nil {
			err = errors.Join(err, fmt.Errorf("stop failed: %w", stopErr))
		}
	}()
	if _, err = checked(s.call(ctx, "colima", args...)); err != nil {
		return err
	}
	return work()
}
func (s *session) profile(ctx context.Context) (string, error) {
	r, err := checked(s.call(ctx, "colima", "list", "--json"))
	if err != nil {
		return "", fmt.Errorf("cannot list colima profiles: %w", err)
	}
	if len(bytes.TrimSpace(r.Stdout)) == 0 {
		return "stopped", nil
	}
	rows, err := objects(r.Stdout)
	if err != nil {
		return "", fmt.Errorf("invalid colima list: %w", err)
	}
	state := "stopped"
	found := false
	for _, row := range rows {
		name, err := profileField(row, "name")
		if err != nil {
			return "", err
		}
		if name != Profile {
			continue
		}
		if found {
			return "", errors.New("duplicate netnone profile")
		}
		found = true
		status, err := profileField(row, "status")
		if err != nil {
			return "", err
		}
		switch status {
		case "Running":
			state = "running"
		case "Stopped":
			state = "stopped"
		default:
			return "", fmt.Errorf("unknown colima status %q", status)
		}
	}
	return state, nil
}

// Colima list's required keys are exact; only extra fields are ignored.
func profileField(row map[string]json.RawMessage, key string) (string, error) {
	var value string
	if err := json.Unmarshal(row[key], &value); err != nil || value == "" {
		return "", fmt.Errorf("invalid or missing colima %s", key)
	}
	return value, nil
}

func directory(path string) (string, error) {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, ":,") {
		return "", fail(2, "refused: mount paths must be absolute directories without ':' or ','")
	}
	p, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fail(2, "refused: mount directory: "+err.Error())
	}
	st, err := os.Stat(p)
	if err != nil || !st.IsDir() || strings.ContainsAny(p, ":,") {
		return "", fail(2, "refused: mount path must resolve to a directory without ':' or ','")
	}
	return p, nil
}
func acquireLock(state string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(state, "run.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fail(3, "refused: another mac-netnone run holds the lock")
		}
		return nil, err
	}
	return f, nil
}

type toolchainID struct {
	Path, SHA string
	Data      []byte
}

func toolchain(path, arch string) (toolchainID, error) {
	if path == "" {
		return toolchainID{SHA: "base"}, nil
	}
	if !filepath.IsAbs(path) {
		return toolchainID{}, fail(2, "toolchain Dockerfile must be an absolute file path")
	}
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		return toolchainID{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return toolchainID{}, err
	}
	if !validToolchain(data, arch) {
		return toolchainID{}, fail(2, "refused: toolchain Dockerfile requires pinned FROM "+BaseImage+" or "+baseImage(arch)+", earlier pinned stages only, and no parser directives or heredocs")
	}
	sum := sha256.Sum256(data)
	return toolchainID{Path: path, SHA: hex.EncodeToString(sum[:]), Data: data}, nil
}

var parserDirective = regexp.MustCompile(`(?i)^#\s*(syntax|check|escape)\s*=`)
var stageName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]*$`)

func validToolchain(data []byte, arch string) bool {
	pinned := func(image string) bool { return image == BaseImage || image == baseImage(arch) }
	seenInstruction, seenFrom := false, false
	stages := map[string]bool{}
	var instruction string
	var continued bool
	scan := bufio.NewScanner(strings.NewReader(string(data)))
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if !seenInstruction && parserDirective.MatchString(line) {
			return false
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Heredoc bodies are not instructions; reject until parsed explicitly.
		if strings.Contains(line, "<<") {
			return false
		}
		seenInstruction = true
		// An escaped trailing backslash is literal; it must not swallow the
		// next instruction (which may itself be an unpinned FROM).
		continued = strings.HasSuffix(line, `\`) && !strings.HasSuffix(line, `\\`)
		if continued {
			instruction += strings.TrimSuffix(line, `\`)
			continue
		}
		instruction += line
		// Docker joins continuation lines before it detects a heredoc, so the
		// check runs on the whole logical instruction (`COPY <\` + `<EOF`).
		if strings.Contains(instruction, "<<") {
			return false
		}
		fields := strings.Fields(instruction)
		instruction = ""
		if len(fields) == 0 {
			return false
		}
		if !strings.EqualFold(fields[0], "FROM") {
			if !seenFrom && !strings.EqualFold(fields[0], "ARG") {
				return false
			}
			continue
		}
		// Only a pinned base may introduce an alias. References cannot declare
		// aliases or use numeric/forward stages, flags, or extra operands.
		if len(fields) == 4 && pinned(fields[1]) && strings.EqualFold(fields[2], "AS") && stageName.MatchString(fields[3]) {
			name := strings.ToLower(fields[3])
			if stages[name] {
				return false
			}
			stages[name] = true
		} else if len(fields) != 2 || (!pinned(fields[1]) && !stages[strings.ToLower(fields[1])]) {
			return false
		}
		seenFrom = true
	}
	return scan.Err() == nil && !continued && instruction == "" && seenFrom
}

// pinToolchain rewrites the pinned index, wherever it appears in validated
// toolchain bytes (single-line or continued FROM, stage FROM, COPY --from), to
// the per-arch manifest digest of that same index. The legacy builder can
// otherwise resolve the index to a local image of the other architecture, and
// a later step then fails with "does not provide the specified platform".
// Validation already admitted the index, so the result stays pinned.
func pinToolchain(data []byte, arch string) []byte {
	return bytes.ReplaceAll(data, []byte(BaseImage), []byte(baseImage(arch)))
}

var imageID = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Record struct {
	Arch          string    `json:"arch"`
	Repo          string    `json:"repo"`
	Task          string    `json:"task"`
	ToolchainPath string    `json:"toolchain_path"`
	ToolchainSHA  string    `json:"toolchain_sha256"`
	Image         string    `json:"image_id"`
	Time          time.Time `json:"time"`
}

func recordKey(repo, sha, arch string) string { return repo + "\n" + sha + "\n" + arch }
func (s *session) records() (map[string]Record, error) {
	data, err := os.ReadFile(filepath.Join(s.state, "prep-records.json"))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]Record{}, nil
	}
	if err != nil {
		return nil, err
	}
	var r map[string]Record
	if err = json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, errors.New("invalid prep records")
	}
	// Records written before architecture selection used the two-part key.
	// Normalize only legacy keys; an explicit arm64 record takes precedence.
	for key, rec := range r {
		if rec.Arch != "" {
			continue
		}
		rec.Arch = "arm64"
		if key == rec.Repo+"\n"+rec.ToolchainSHA {
			delete(r, key)
			key = recordKey(rec.Repo, rec.ToolchainSHA, rec.Arch)
			if _, exists := r[key]; exists {
				continue
			}
		}
		r[key] = rec
	}
	return r, nil
}
func (s *session) save(rec Record) error {
	records, err := s.records()
	if err != nil {
		return err
	}
	records[recordKey(rec.Repo, rec.ToolchainSHA, rec.Arch)] = rec
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.state, ".records-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(s.state, "prep-records.json"))
}
func (s *session) status(ctx context.Context) error {
	p, err := s.profile(ctx)
	if err != nil {
		return err
	}
	records, err := s.records()
	if err != nil {
		return err
	}
	held := false
	f, err := os.OpenFile(filepath.Join(s.state, "run.lock"), os.O_RDONLY, 0)
	if err == nil {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if errors.Is(err, unix.EWOULDBLOCK) {
			held = true
		} else if err != nil {
			f.Close()
			return err
		}
		f.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return json.NewEncoder(s.e.Out).Encode(struct {
		Profile, StateDir string
		LockHeld          bool
		PrepRecords       map[string]Record
	}{p, s.state, held, records})
}
