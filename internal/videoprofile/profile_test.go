package videoprofile

import (
	"strings"
	"testing"
	"time"

	"github.com/relux-works/mac-infra/internal/loadprofile"
)

const videoPSFixture = `
  10     1 root          0.0   0.1   1024 01:00:00 /sbin/launchd
 100    10 _windowserver 62.5   2.5 524288 00:10:00 /System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer
 200    10 alexis       88.0  10.0 2097152 02:00:00 /Applications/Docker.app/Contents/MacOS/com.docker.backend
 201   200 alexis       21.0   2.0 262144 00:09:00 /Applications/Docker.app/Contents/MacOS/vpnkit
 300    10 alexis       40.0   4.0 786432 00:05:00 /Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Helper
 400    10 alexis        8.0   1.0 131072 00:05:00 /System/Library/CoreServices/Dock.app/Contents/MacOS/Dock
`

func TestDefaultCaptureCommandsAreAbsoluteReadOnlyAndIncludeLogsOnlyWhenRequested(t *testing.T) {
	withoutLogs := DefaultCaptureCommands(false)
	withLogs := DefaultCaptureCommands(true)
	if len(withoutLogs) == 0 {
		t.Fatal("DefaultCaptureCommands returned no commands")
	}
	if len(withLogs) <= len(withoutLogs) {
		t.Fatalf("commands with logs = %d, without logs = %d; want more with logs", len(withLogs), len(withoutLogs))
	}

	for _, command := range withLogs {
		if command.Executable == "" || command.Executable[0] != '/' {
			t.Fatalf("%s executable = %q, want absolute path", command.Name, command.Executable)
		}
		for _, forbidden := range []string{"sudo", "kill", "killall", "launchctl", "osascript"} {
			if strings.HasSuffix(command.Executable, "/"+forbidden) {
				t.Fatalf("%s uses forbidden executable %q", command.Name, command.Executable)
			}
		}
		if command.Filename == "" {
			t.Fatalf("%s has empty filename", command.Name)
		}
	}
}

func TestCaptureDirUsesUTCDefaultRoot(t *testing.T) {
	got := CaptureDir("", time.Date(2026, 6, 28, 17, 15, 30, 0, time.FixedZone("MSK", 3*60*60)))
	want := ".temp/mac-video-profile/capture-20260628T141530Z"
	if got != want {
		t.Fatalf("CaptureDir = %q, want %q", got, want)
	}
}

func TestProcessGroupsCoverExpectedVideoStutterSuspects(t *testing.T) {
	queries := strings.Join(InterestingQueries(), "\n")
	for _, want := range []string{"WindowServer", "com.docker", "qemu-system", "VTDecoderXPCService", "Google Chrome"} {
		if !strings.Contains(queries, want) {
			t.Fatalf("InterestingQueries missing %q in:\n%s", want, queries)
		}
	}
}

func TestSummarizeGroupsFindsHotCompositorAndDockerProcesses(t *testing.T) {
	processes, err := loadprofile.ParsePS([]byte(videoPSFixture))
	if err != nil {
		t.Fatalf("ParsePS error = %v", err)
	}

	summaries := SummarizeGroups(processes, 30)
	if len(summaries) == 0 {
		t.Fatal("SummarizeGroups returned no summaries")
	}

	byName := map[string]GroupSummary{}
	for _, summary := range summaries {
		byName[summary.Group.Name] = summary
	}
	if len(byName["compositor"].Hot) != 1 || byName["compositor"].Hot[0].PID != 100 {
		t.Fatalf("compositor hot processes = %#v, want WindowServer pid 100", byName["compositor"].Hot)
	}
	if len(byName["docker-virtualization"].Hot) != 1 || byName["docker-virtualization"].Hot[0].PID != 200 {
		t.Fatalf("docker hot processes = %#v, want Docker backend pid 200", byName["docker-virtualization"].Hot)
	}
}

func TestTopInterestingReturnsSuspectsByCPU(t *testing.T) {
	processes, err := loadprofile.ParsePS([]byte(videoPSFixture))
	if err != nil {
		t.Fatalf("ParsePS error = %v", err)
	}

	top := TopInteresting(processes, 3)
	if len(top) != 3 {
		t.Fatalf("len(top) = %d, want 3", len(top))
	}
	if top[0].PID != 200 || top[1].PID != 100 || top[2].PID != 300 {
		t.Fatalf("top pids = %d, %d, %d; want 200, 100, 300", top[0].PID, top[1].PID, top[2].PID)
	}
}
