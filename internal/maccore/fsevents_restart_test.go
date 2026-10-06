package maccore

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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

func requireSignalCount(t *testing.T, logPath string, count int) {
	t.Helper()
	calls := readCommandLog(t, logPath)
	if strings.Count(calls, "/bin/kill -TERM 368\n") != count || strings.Count(calls, "/bin/kill ") != count {
		t.Fatalf("want exactly %d signals to pid 368 only, calls = %q", count, calls)
	}
	if strings.Contains(calls, "launchctl") || strings.Contains(calls, "killall") || strings.Contains(calls, "pkill") {
		t.Fatalf("restart must never kickstart or signal a process family: %q", calls)
	}
}

// One exact SIGTERM tolerates a respawn gap; success requires new PID and lower RSS.
// Fake commands prove the contract here; live SIP permission is checked separately.
func TestRestartFSEventsAboveThresholdSignalsAndReportsNewPID(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "commands.log")
	before := psLine(368, 4*1024*1024, fsevents.DaemonPath)
	withFakePS(t, logPath, before, before, psLine(1, 10, "/sbin/launchd"), psLine(4242, 2048, fsevents.DaemonPath))
	results, err := restartFSEvents(false, 0)
	requireSignalCount(t, logPath, 1)
	if err != nil {
		t.Fatalf("err = %v; results = %+v", err, results)
	}
	if last := results[len(results)-1]; !strings.Contains(last.Output, "pid=4242 rss=2.0MB") {
		t.Fatalf("after state = %+v", last)
	}
}

// Below-threshold RSS and a missing daemon refuse without signalling;
// force bypasses only RSS admission, never target existence.
func TestRestartFSEventsSIGTERMAdmission(t *testing.T) {
	for name, row := range map[string]struct {
		output    string
		force     bool
		errorText string
	}{
		"healthy":        {psLine(368, 1024, fsevents.DaemonPath), false, "below threshold"},
		"missing":        {psLine(1, 10, "/sbin/launchd"), false, "process not found"},
		"missing-forced": {psLine(1, 10, "/sbin/launchd"), true, "process not found"},
	} {
		t.Run(name, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "commands.log")
			withFakePS(t, logPath, row.output)
			if _, err := restartFSEvents(row.force, 0); err == nil || !strings.Contains(err.Error(), row.errorText) {
				t.Fatalf("err = %v, want %q", err, row.errorText)
			}
			requireSignalCount(t, logPath, 0)
		})
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	before := psLine(368, 4096, fsevents.DaemonPath)
	withFakePS(t, logPath, before, before, psLine(4242, 1024, fsevents.DaemonPath))
	if results, err := restartFSEvents(true, 0); err != nil {
		t.Fatalf("err = %v; results = %+v", err, results)
	}
	requireSignalCount(t, logPath, 1)
}

// Missing respawn, unchanged PID and no RSS relief time out after exactly
// one signal; failure never authorizes a second signal.
func TestRestartFSEventsRespawnFailureNeverSignalsTwice(t *testing.T) {
	before := psLine(368, 4*1024*1024, fsevents.DaemonPath)
	for name, after := range map[string]string{
		"missing":       psLine(1, 10, "/sbin/launchd"),
		"same-pid":      psLine(368, 1024, fsevents.DaemonPath),
		"no-rss-relief": psLine(4242, 4*1024*1024, fsevents.DaemonPath),
	} {
		t.Run(name, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "commands.log")
			withFakePS(t, logPath, before, before, after)
			_, err := restartFSEvents(false, 0)
			if err == nil || !strings.Contains(err.Error(), "timed out waiting for a new fseventsd PID with lower RSS") {
				t.Fatalf("err = %v, want bounded verification failure", err)
			}
			requireSignalCount(t, logPath, 1)
		})
	}
}

// Basename lookalikes, wrong owner/parent, unsafe PID and ambiguous candidates
// are refused even with force; inspection cannot widen the signal target.
func TestRestartFSEventsRefusesWrongProcessIdentity(t *testing.T) {
	good := psLine(368, 4*1024*1024, fsevents.DaemonPath)
	for name, output := range map[string]string{
		"wrong-path":   psLine(368, 4*1024*1024, "/tmp/fseventsd"),
		"wrong-user":   strings.Replace(good, " root ", " alexis ", 1),
		"wrong-parent": strings.Replace(good, "368 1 ", "368 2 ", 1),
		"unsafe-pid":   psLine(1, 4*1024*1024, fsevents.DaemonPath),
		"ambiguous":    good + ";" + psLine(4242, 4*1024*1024, fsevents.DaemonPath),
	} {
		t.Run(name, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "commands.log")
			withFakePS(t, logPath, output)
			if _, err := restartFSEvents(true, 0); err == nil || !strings.Contains(err.Error(), "identity") {
				t.Fatalf("err = %v, want identity refusal", err)
			}
			requireSignalCount(t, logPath, 0)
		})
	}
}

// Revalidation refuses disappearance, changed PID, an impostor and RSS
// falling below the guard, with no signal to either process.
func TestRestartFSEventsRevalidatesBeforeSignal(t *testing.T) {
	before := psLine(368, 4*1024*1024, fsevents.DaemonPath)
	for name, row := range map[string]struct{ output, errorText string }{
		"missing":     {psLine(1, 10, "/sbin/launchd"), "changed before signal"},
		"changed-pid": {psLine(4242, 4*1024*1024, fsevents.DaemonPath), "changed before signal"},
		"impostor":    {psLine(368, 4*1024*1024, "/tmp/fseventsd"), "identity"},
		"rss-fell":    {psLine(368, 1024, fsevents.DaemonPath), "below threshold"},
	} {
		t.Run(name, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "commands.log")
			withFakePS(t, logPath, before, row.output)
			if _, err := restartFSEvents(false, 0); err == nil || !strings.Contains(err.Error(), row.errorText) {
				t.Fatalf("err = %v, want %q", err, row.errorText)
			}
			requireSignalCount(t, logPath, 0)
		})
	}
}

// Signal denial surfaces immediately without another signal or success.
func TestRestartFSEventsSignalFailure(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "commands.log")
	before := psLine(368, 4*1024*1024, fsevents.DaemonPath)
	withFakePS(t, logPath, before, before)
	t.Setenv("MAC_INFRA_TEST_KILL_FAIL", "1")
	if _, err := restartFSEvents(false, 0); err == nil || !strings.Contains(err.Error(), "signal refused") {
		t.Fatalf("err = %v, want signal denial", err)
	}
	requireSignalCount(t, logPath, 1)
}

// A foreign process appearing during the respawn wait causes an identity
// error after the one authorized signal, rather than success or another signal.
func TestRestartFSEventsRefusesImpostorAfterSignal(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "commands.log")
	before := psLine(368, 4*1024*1024, fsevents.DaemonPath)
	withFakePS(t, logPath, before, before, psLine(4242, 1024, "/tmp/fseventsd"))
	if _, err := restartFSEvents(false, 0); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("err = %v, want post-signal identity refusal", err)
	}
	requireSignalCount(t, logPath, 1)
}

// An inspection error after SIGTERM surfaces as an error, with no second signal.
func TestRestartFSEventsInspectionFailureAfterSignal(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "commands.log")
	before := psLine(368, 4*1024*1024, fsevents.DaemonPath)
	withFakePS(t, logPath, before, before, psLine(4242, 1024, fsevents.DaemonPath))
	t.Setenv("MAC_INFRA_TEST_PS_FAIL_AT", "2")
	if _, err := restartFSEvents(false, 0); err == nil || !strings.Contains(err.Error(), "ps unavailable after signal") {
		t.Fatalf("err = %v, want post-signal inspection failure", err)
	}
	requireSignalCount(t, logPath, 1)
}

// A ps helper delayed beyond the respawn budget is cancelled; its eventual
// new-PID output cannot establish success, and no additional signal is sent.
func TestRestartFSEventsSlowInspectionRespectsRespawnBudget(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "commands.log")
	before := psLine(368, 4*1024*1024, fsevents.DaemonPath)
	withFakePS(t, logPath, before, before, psLine(4242, 1024, fsevents.DaemonPath))
	t.Setenv("MAC_INFRA_TEST_PS_DELAY_AT", "2")
	t.Setenv("MAC_INFRA_TEST_PS_DELAY", "10s")
	start := time.Now()
	if _, err := restartFSEvents(false, 0); err == nil || !strings.Contains(err.Error(), "timed out waiting for a new fseventsd PID with lower RSS") || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want bounded respawn timeout wrapping the inspection deadline", err)
	}
	if elapsed := time.Since(start); elapsed > fseventsRespawnTimeout+2*time.Second {
		t.Fatalf("elapsed = %s exceeded respawn budget plus process-start tolerance", elapsed)
	}
	requireSignalCount(t, logPath, 1)
}

// Failed inspection aborts before any privileged signal.
func TestRestartFSEventsSIGTERMPSFailure(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "commands.log")
	withFakeCoreCommand(t, logPath)
	t.Setenv("MAC_INFRA_TEST_PS_FAIL", "1")
	if _, err := restartFSEvents(true, 0); err == nil || !strings.Contains(err.Error(), "inspect fseventsd") {
		t.Fatalf("err = %v", err)
	}
	requireSignalCount(t, logPath, 0)
}
