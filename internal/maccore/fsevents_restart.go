package maccore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/relux-works/mac-infra/internal/fsevents"
	"github.com/relux-works/mac-infra/internal/loadprofile"
)

const (
	FSEventsLaunchdLabel    = "com.apple.fseventsd"
	psPath                  = "/bin/ps"
	fseventsRespawnTimeout  = 5 * time.Second
	fseventsRespawnInterval = 100 * time.Millisecond
)

var fseventsRestartMu sync.Mutex

// FSEventsDaemonState is the fseventsd process as observed through ps.
type FSEventsDaemonState struct {
	Found    bool
	PID      int
	RSSBytes int64
	CPU      float64
	Elapsed  string
}

// InspectFSEventsDaemon reads fseventsd pid/rss/cpu through ps. It works for
// the unprivileged CLI, the watchdog check, and the root daemon alike.
func InspectFSEventsDaemon() (FSEventsDaemonState, CommandResult, error) {
	return inspectFSEventsDaemonWithin(commandTimeout)
}

func inspectFSEventsDaemonWithin(timeout time.Duration) (FSEventsDaemonState, CommandResult, error) {
	result, err := runCoreCommandWithTimeout(timeout, psPath, loadprofile.PSArgs()...)
	if err != nil {
		return FSEventsDaemonState{}, result, fmt.Errorf("inspect fseventsd: %w", err)
	}
	processes, err := loadprofile.ParsePS([]byte(result.Output))
	if err != nil {
		return FSEventsDaemonState{}, result, fmt.Errorf("inspect fseventsd: %w", err)
	}
	// The daemon's own ps output is large; keep the command log entry short.
	result.Output = fmt.Sprintf("%d processes", len(processes))
	// Diagnostics can match a basename, but a privileged signal requires the
	// canonical Apple executable, root owner, launchd parent and one safe PID.
	var daemon loadprofile.Process
	for _, process := range processes {
		command := strings.Fields(process.Command)
		if len(command) == 0 || filepath.Base(command[0]) != "fseventsd" {
			continue
		}
		if command[0] != fsevents.DaemonPath || process.User != "root" || process.PPID != 1 || process.PID <= 1 || process.RSSKB <= 0 {
			return FSEventsDaemonState{}, result, fmt.Errorf("refusing fseventsd identity: pid %d is not the canonical root launchd daemon", process.PID)
		}
		if daemon.PID != 0 {
			return FSEventsDaemonState{}, result, fmt.Errorf("refusing ambiguous fseventsd identity: multiple daemon candidates")
		}
		daemon = process
	}
	if daemon.PID == 0 {
		return FSEventsDaemonState{}, result, nil
	}
	return FSEventsDaemonState{
		Found:    true,
		PID:      daemon.PID,
		RSSBytes: daemon.RSSKB * 1024,
		CPU:      daemon.CPU,
		Elapsed:  daemon.Elapsed,
	}, result, nil
}

func RestartFSEvents(cfg ServiceConfig, force bool, rssThresholdBytes int64) (Response, error) {
	return Call(cfg, Request{
		Action:            ActionRestartFSEvents,
		Force:             force,
		RSSThresholdBytes: rssThresholdBytes,
	})
}

// restartFSEvents is the daemon-side allowlisted action. Without --force it
// refuses unless fseventsd RSS is at or above the threshold. Force bypasses
// only RSS admission, never target identity or respawn verification.
func restartFSEvents(force bool, rssThresholdBytes int64) ([]CommandResult, error) {
	// Concurrent callers must re-inspect after the preceding attempt completes.
	fseventsRestartMu.Lock()
	defer fseventsRestartMu.Unlock()
	if rssThresholdBytes <= 0 {
		rssThresholdBytes = fsevents.DefaultRSSCriticalBytes
	}
	var results []CommandResult

	before, result, err := InspectFSEventsDaemon()
	results = append(results, result)
	if err != nil {
		return results, err
	}
	results = append(results, describeFSEventsState("before", before))
	if !before.Found {
		return results, fmt.Errorf("refusing fseventsd restart: process not found")
	}
	if !force {
		if before.RSSBytes < rssThresholdBytes {
			return results, fmt.Errorf("refusing fseventsd restart: rss %s is below threshold %s; pass --force to override",
				loadprofile.FormatBytes(before.RSSBytes), loadprofile.FormatBytes(rssThresholdBytes))
		}
	}

	// Re-resolve immediately before signalling; do not signal a stale PID or
	// a newly healthy daemon. This is a userspace identity check, not a PID handle.
	current, result, err := InspectFSEventsDaemon()
	results = append(results, result)
	if err != nil {
		return results, err
	}
	if !current.Found || current.PID != before.PID {
		return results, fmt.Errorf("refusing fseventsd restart: daemon changed before signal")
	}
	if !force && current.RSSBytes < rssThresholdBytes {
		return results, fmt.Errorf("refusing fseventsd restart: rss fell below threshold before signal")
	}
	before = current
	results = append(results, describeFSEventsState("validated", before))
	// SIP can deny launchctl kickstart of Apple services even to root. A single
	// SIGTERM targets only the revalidated daemon; launchd owns its respawn.
	result, err = runCoreCommand("/bin/kill", "-TERM", strconv.Itoa(before.PID))
	results = append(results, result)
	if err != nil {
		return results, err
	}

	deadline := time.Now().Add(fseventsRespawnTimeout)
	var after FSEventsDaemonState
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			results = append(results, describeFSEventsState("after", after))
			return results, fmt.Errorf("timed out waiting for a new fseventsd PID with lower RSS after one SIGTERM (limit %s)", fseventsRespawnTimeout)
		}
		after, result, err = inspectFSEventsDaemonWithin(remaining)
		if err != nil {
			results = append(results, result)
			if errors.Is(err, context.DeadlineExceeded) {
				return results, fmt.Errorf("timed out waiting for a new fseventsd PID with lower RSS after one SIGTERM (limit %s): %w", fseventsRespawnTimeout, err)
			}
			return results, err
		}
		if time.Now().Before(deadline) && after.Found && after.PID != before.PID && after.RSSBytes < before.RSSBytes {
			results = append(results, result, describeFSEventsState("after", after))
			return results, nil
		}
		remaining = time.Until(deadline)
		if remaining <= 0 {
			results = append(results, result, describeFSEventsState("after", after))
			return results, fmt.Errorf("timed out waiting for a new fseventsd PID with lower RSS after one SIGTERM (limit %s)", fseventsRespawnTimeout)
		}
		time.Sleep(min(fseventsRespawnInterval, remaining))
	}
}

func describeFSEventsState(phase string, state FSEventsDaemonState) CommandResult {
	if !state.Found {
		return CommandResult{Command: "fseventsd " + phase, Output: "not-found"}
	}
	return CommandResult{
		Command: "fseventsd " + phase,
		Output:  fmt.Sprintf("pid=%d rss=%s cpu=%.1f%% elapsed=%s", state.PID, loadprofile.FormatBytes(state.RSSBytes), state.CPU, state.Elapsed),
	}
}
