package maccore

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/fsevents"
)

func psLine(pid int, rssKB int64, command string) string {
	return "  " + strconv.Itoa(pid) + " 1 root 1.0 0.1 " + strconv.FormatInt(rssKB, 10) + " 01:00 " + command
}

func withFakePS(t *testing.T, logPath string, outputs ...string) {
	t.Helper()
	withFakeCoreCommand(t, logPath)
	t.Setenv("MAC_INFRA_TEST_PS_OUTPUTS", strings.Join(outputs, "|"))
	t.Setenv("MAC_INFRA_TEST_PS_COUNTER", filepath.Join(t.TempDir(), "ps.counter"))
}

// Below the threshold and without force, the daemon refuses and never runs
// launchctl: a healthy fseventsd must not be restarted by a stray call.
func TestRestartFSEventsRefusesBelowThresholdWithoutForce(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "commands.log")
	withFakePS(t, logPath, psLine(368, 1024*1024, fsevents.DaemonPath))

	results, err := restartFSEvents(false, 4*1024*1024*1024)

	if err == nil || !strings.Contains(err.Error(), "below threshold") {
		t.Fatalf("err = %v, want below-threshold refusal", err)
	}
	if calls := readCommandLog(t, logPath); strings.Contains(calls, "launchctl") {
		t.Fatalf("launchctl must not run on refusal: %q", calls)
	}
	if len(results) != 2 || !strings.Contains(results[1].Output, "pid=368") {
		t.Fatalf("results = %+v", results)
	}
}

// A missing fseventsd is refused without force; with force the kickstart
// still runs (launchd will start it), and the after-state is reported.
func TestRestartFSEventsMissingDaemon(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "commands.log")
	withFakePS(t, logPath, psLine(1, 10, "/sbin/launchd"))
	if _, err := restartFSEvents(false, 0); err == nil || !strings.Contains(err.Error(), "process not found") {
		t.Fatalf("err = %v, want not-found refusal", err)
	}

	logPath = filepath.Join(t.TempDir(), "commands.log")
	withFakePS(t, logPath, psLine(1, 10, "/sbin/launchd"), psLine(999, 100, fsevents.DaemonPath))
	t.Setenv("MAC_INFRA_TEST_LAUNCHCTL_PRINT", "enabled")
	results, err := restartFSEvents(true, 0)
	if err != nil {
		t.Fatalf("forced restart err = %v; results = %+v", err, results)
	}
	if calls := readCommandLog(t, logPath); !strings.Contains(calls, "/bin/launchctl kickstart -k system/com.apple.fseventsd") {
		t.Fatalf("calls = %q", calls)
	}
	if last := results[len(results)-1]; !strings.Contains(last.Output, "pid=999") {
		t.Fatalf("after state = %+v", last)
	}
}

// At or above the threshold the restart runs exactly one fixed launchctl
// kickstart and reports a changed pid; a zero threshold selects the default.
func TestRestartFSEventsAboveThresholdKickstartsAndReportsNewPID(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "commands.log")
	fourGB := int64(4 * 1024 * 1024 * 1024)
	withFakePS(t, logPath, psLine(368, fourGB/1024, fsevents.DaemonPath), psLine(4242, 2048, fsevents.DaemonPath))

	results, err := restartFSEvents(false, 0)

	if err != nil {
		t.Fatalf("err = %v; results = %+v", err, results)
	}
	calls := readCommandLog(t, logPath)
	if strings.Count(calls, "/bin/launchctl") != 1 || !strings.Contains(calls, "kickstart -k system/com.apple.fseventsd") {
		t.Fatalf("calls = %q", calls)
	}
	if strings.Contains(calls, "pkill") || strings.Contains(calls, "kill ") {
		t.Fatalf("restart must go through launchctl only: %q", calls)
	}
	joined := ""
	for _, result := range results {
		joined += result.Command + ": " + result.Output + "\n"
	}
	if !strings.Contains(joined, "fseventsd before: pid=368 rss=4.0GB") || !strings.Contains(joined, "fseventsd after: pid=4242") {
		t.Fatalf("results = %s", joined)
	}
}

// An unchanged pid after kickstart is an error, not a silent success.
func TestRestartFSEventsUnchangedPIDIsError(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "commands.log")
	withFakePS(t, logPath, psLine(368, 8*1024*1024, fsevents.DaemonPath))

	_, err := restartFSEvents(false, 0)

	if err == nil || !strings.Contains(err.Error(), "did not change") {
		t.Fatalf("err = %v", err)
	}
}

// A ps failure surfaces as an inspect error before any privileged action.
func TestRestartFSEventsPSFailureAbortsBeforeKickstart(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "commands.log")
	withFakeCoreCommand(t, logPath)
	t.Setenv("MAC_INFRA_TEST_PS_FAIL", "1")

	_, err := restartFSEvents(true, 0)

	if err == nil || !strings.Contains(err.Error(), "inspect fseventsd") {
		t.Fatalf("err = %v", err)
	}
	if calls := readCommandLog(t, logPath); strings.Contains(calls, "launchctl") {
		t.Fatalf("launchctl must not run when ps fails: %q", calls)
	}
}
