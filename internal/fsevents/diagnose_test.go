package fsevents

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/loadprofile"
)

func proc(pid int, cpu float64, rssKB int64, command string) loadprofile.Process {
	return loadprofile.Process{PID: pid, PPID: 1, User: "root", CPU: cpu, RSSKB: rssKB, Elapsed: "01:00", Command: command}
}

const gb = 1024 * 1024 * 1024

// FindDaemon matches fseventsd by executable basename and ignores processes
// that merely mention fseventsd in their arguments.
func TestFindDaemonMatchesExecutableBasenameOnly(t *testing.T) {
	processes := []loadprofile.Process{
		proc(10, 0, 100, "/usr/bin/grep fseventsd"),
		proc(368, 99, 1024, DaemonPath),
	}
	daemon, ok := FindDaemon(processes)
	if !ok || daemon.PID != 368 {
		t.Fatalf("FindDaemon = %+v, %t; want pid 368", daemon, ok)
	}
	if _, ok := FindDaemon(processes[:1]); ok {
		t.Fatalf("FindDaemon matched a grep command line")
	}
}

// Verdict escalation follows the RSS thresholds exactly at the boundary:
// below warn is ok, at warn is warning, at critical is critical.
func TestAnalyzeRSSThresholdBoundaries(t *testing.T) {
	thresholds := Thresholds{RSSWarnBytes: 2 * gb, RSSCriticalBytes: 4 * gb, CPUWarnPercent: 50, TempBuildWarnBytes: 2 * gb}
	tests := []struct {
		name  string
		rssKB int64
		want  Verdict
	}{
		{name: "below-warn", rssKB: 2*gb/1024 - 1, want: VerdictOK},
		{name: "at-warn", rssKB: 2 * gb / 1024, want: VerdictWarning},
		{name: "at-critical", rssKB: 4 * gb / 1024, want: VerdictCritical},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Analyze([]loadprofile.Process{proc(368, 1, tt.rssKB, DaemonPath)}, nil, TempBuild{Dir: "/tmp"}, thresholds)
			if d.Verdict != tt.want {
				t.Fatalf("verdict = %s, want %s; findings=%v", d.Verdict, tt.want, d.Findings)
			}
			if tt.want == VerdictCritical && !containsSubstring(d.Recommendations, "fseventsd-restart") {
				t.Fatalf("critical verdict must recommend fseventsd-restart: %v", d.Recommendations)
			}
			if tt.want != VerdictCritical && containsSubstring(d.Recommendations, "fseventsd-restart") {
				t.Fatalf("non-critical verdict must not recommend a restart: %v", d.Recommendations)
			}
		})
	}
}

// A missing fseventsd is reported as a warning finding, never as ok and never
// as a crash on the nil daemon pointer.
func TestAnalyzeMissingDaemonIsWarning(t *testing.T) {
	d := Analyze([]loadprofile.Process{proc(1, 0, 10, "/sbin/launchd")}, nil, TempBuild{Dir: "/tmp"}, DefaultThresholds())
	if d.DaemonFound || d.Daemon != nil {
		t.Fatalf("daemon should be absent: %+v", d)
	}
	if d.Verdict != VerdictWarning || !containsSubstring(d.Findings, "not found") {
		t.Fatalf("verdict = %s findings = %v", d.Verdict, d.Findings)
	}
	var buf bytes.Buffer
	PrintDiagnostic(&buf, d)
	if !strings.Contains(buf.String(), "fseventsd_pid: not-found") {
		t.Fatalf("output = %s", buf.String())
	}
}

// Hot fseventsd CPU produces the explicit do-not-throttle recommendation
// because a starved daemon drops events and triggers client rescans.
func TestAnalyzeHotCPUWarnsAgainstThrottling(t *testing.T) {
	d := Analyze([]loadprofile.Process{proc(368, 101, 1024, DaemonPath)}, nil, TempBuild{Dir: "/tmp"}, DefaultThresholds())
	if d.Verdict != VerdictWarning {
		t.Fatalf("verdict = %s", d.Verdict)
	}
	if !containsSubstring(d.Recommendations, "do not renice or throttle") {
		t.Fatalf("recommendations = %v", d.Recommendations)
	}
}

// Consumer classification: the colima inotify daemon is recognised only with
// the --inotify flag, a plain colima process is not a consumer, and go test
// is reported as an event generator without escalating the verdict.
func TestConsumersClassification(t *testing.T) {
	processes := []loadprofile.Process{
		proc(1, 0, 1, "/opt/homebrew/bin/colima daemon start default --inotify --inotify-runtime docker --inotify-dir /Users/x/"),
		proc(2, 0, 1, "/opt/homebrew/bin/colima daemon start default --vmnet"),
		proc(3, 0, 1, "/opt/homebrew/bin/colima status"),
		proc(4, 0, 1, "go test -p 2 ./..."),
		proc(5, 0, 1, "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mds_stores"),
		proc(6, 0, 1, "/Applications/Saby Center.app/Contents/MacOS/sabycenter start --daemon"),
		proc(7, 0, 1, "git fsmonitor--daemon run"),
		proc(8, 0, 1, "/usr/bin/go version"),
	}
	consumers := Consumers(processes)
	got := map[int]string{}
	for _, consumer := range consumers {
		got[consumer.Process.PID] = consumer.Kind
	}
	want := map[int]string{1: "colima-inotify", 4: "go-test", 5: "spotlight", 6: "saby-center", 7: "git-fsmonitor"}
	if len(got) != len(want) {
		t.Fatalf("consumers = %v, want %v", got, want)
	}
	for pid, kind := range want {
		if got[pid] != kind {
			t.Fatalf("pid %d kind = %q, want %q", pid, got[pid], kind)
		}
	}

	d := Analyze(append(processes, proc(368, 1, 1024, DaemonPath)), nil, TempBuild{Dir: "/tmp"}, DefaultThresholds())
	if d.Verdict != VerdictWarning {
		t.Fatalf("colima inotify must produce a warning verdict, got %s", d.Verdict)
	}
	if !containsSubstring(d.Recommendations, "mountInotify: false") {
		t.Fatalf("recommendations = %v", d.Recommendations)
	}
	dOnlyGoTest := Analyze([]loadprofile.Process{processes[3], proc(368, 1, 1024, DaemonPath)}, nil, TempBuild{Dir: "/tmp"}, DefaultThresholds())
	if dOnlyGoTest.Verdict != VerdictOK {
		t.Fatalf("go test alone must not escalate verdict, got %s: %v", dOnlyGoTest.Verdict, dOnlyGoTest.Findings)
	}
}

// ParseColimaConfig reads the two keys that matter, ignores comments and
// commented-out example mounts, and treats a missing mounts key as the
// whole-$HOME default rather than as an empty mount list.
func TestParseColimaConfig(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantInotify bool
		wantMounts  []string
		wantErr     string
	}{
		{
			name: "inotify-with-explicit-mounts",
			input: "# comment\nmountType: virtiofs\nmountInotify: true\n" +
				"# mounts:\n#   - location: ~/secrets\nmounts:\n  - location: ~/src/tetris\n    writable: true\n  - location: ~/src/board\n    writable: true\ncpuType: \"\"\n",
			wantInotify: true,
			wantMounts:  []string{"~/src/tetris", "~/src/board"},
		},
		{
			name:        "inotify-off-empty-mounts",
			input:       "mountInotify: false\nmounts: []\n",
			wantInotify: false,
			wantMounts:  []string{},
		},
		{
			name:        "mounts-key-missing",
			input:       "mountInotify: true\n",
			wantInotify: true,
			wantMounts:  []string{},
			wantErr:     "mounts key not found",
		},
		{
			name:        "mounts-list-does-not-leak-into-next-key",
			input:       "mounts:\n  - location: ~/a\nprovision:\n  - mode: system\n    location: ~/not-a-mount\n",
			wantInotify: false,
			wantMounts:  []string{"~/a"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inotify, mounts, errText := ParseColimaConfig(strings.NewReader(tt.input))
			if inotify != tt.wantInotify {
				t.Fatalf("mountInotify = %t, want %t", inotify, tt.wantInotify)
			}
			if strings.Join(mounts, ",") != strings.Join(tt.wantMounts, ",") {
				t.Fatalf("mounts = %v, want %v", mounts, tt.wantMounts)
			}
			if tt.wantErr == "" && errText != "" {
				t.Fatalf("unexpected error text %q", errText)
			}
			if tt.wantErr != "" && !strings.Contains(errText, tt.wantErr) {
				t.Fatalf("error text = %q, want %q", errText, tt.wantErr)
			}
		})
	}
}

// ScanColimaProfiles reports an unreadable profile as a per-profile error
// instead of failing the whole scan, and returns nil when no profile exists.
func TestScanColimaProfilesHandlesUnreadableAndMissing(t *testing.T) {
	home := t.TempDir()
	if profiles := ScanColimaProfiles(home); profiles != nil {
		t.Fatalf("expected nil for missing ~/.colima, got %v", profiles)
	}
	good := filepath.Join(home, ".colima", "default")
	bad := filepath.Join(home, ".colima", "locked")
	for _, dir := range []string{good, bad} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(good, "colima.yaml"), []byte("mountInotify: true\nmounts: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, "colima.yaml"), []byte("mountInotify: true\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root can read 0000 files; unreadable case not testable")
	}
	profiles := ScanColimaProfiles(home)
	if len(profiles) != 2 {
		t.Fatalf("profiles = %v", profiles)
	}
	if !profiles[0].MountInotify || profiles[0].Error != "" {
		t.Fatalf("good profile = %+v", profiles[0])
	}
	if profiles[1].Error == "" || profiles[1].MountInotify {
		t.Fatalf("unreadable profile must report an error and not claim inotify: %+v", profiles[1])
	}

	d := Analyze([]loadprofile.Process{proc(368, 1, 1024, DaemonPath)}, profiles, TempBuild{Dir: "/tmp"}, DefaultThresholds())
	if !containsSubstring(d.Findings, "mounts the whole $HOME") {
		t.Fatalf("findings = %v", d.Findings)
	}
}

// ScanTempBuild counts only go-build* directories, sizes regular files, and
// reports an empty dir argument as an error instead of scanning cwd.
func TestScanTempBuild(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "go-build123", "b001"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go-build123", "b001", "x.test"), bytes.Repeat([]byte("a"), 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go-build-file"), []byte("not a dir"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "other"), 0o755); err != nil {
		t.Fatal(err)
	}
	result := ScanTempBuild(dir)
	if result.Error != "" || result.Count != 1 || result.Bytes != 4096 {
		t.Fatalf("result = %+v", result)
	}
	if empty := ScanTempBuild(""); empty.Error == "" {
		t.Fatalf("empty dir must be an error: %+v", empty)
	}

	thresholds := DefaultThresholds()
	thresholds.TempBuildWarnBytes = 4096
	d := Analyze([]loadprofile.Process{proc(368, 1, 1024, DaemonPath)}, nil, result, thresholds)
	if d.Verdict != VerdictWarning || !containsSubstring(d.Recommendations, "go-build* leftovers") {
		t.Fatalf("verdict = %s recommendations = %v", d.Verdict, d.Recommendations)
	}
	errored := Analyze([]loadprofile.Process{proc(368, 1, 1024, DaemonPath)}, nil, TempBuild{Dir: "", Error: "empty temp dir"}, thresholds)
	if errored.Verdict != VerdictOK {
		t.Fatalf("a temp scan error must not be counted as bloat: %s %v", errored.Verdict, errored.Findings)
	}
}

func containsSubstring(items []string, needle string) bool {
	for _, item := range items {
		if strings.Contains(item, needle) {
			return true
		}
	}
	return false
}
