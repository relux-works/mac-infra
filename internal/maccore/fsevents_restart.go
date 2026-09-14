package maccore

import (
	"fmt"

	"github.com/relux-works/mac-infra/internal/fsevents"
	"github.com/relux-works/mac-infra/internal/loadprofile"
)

const (
	FSEventsLaunchdLabel = "com.apple.fseventsd"
	psPath               = "/bin/ps"
)

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
	result, err := runCoreCommand(psPath, loadprofile.PSArgs()...)
	if err != nil {
		return FSEventsDaemonState{}, result, fmt.Errorf("inspect fseventsd: %w", err)
	}
	processes, err := loadprofile.ParsePS([]byte(result.Output))
	if err != nil {
		return FSEventsDaemonState{}, result, fmt.Errorf("inspect fseventsd: %w", err)
	}
	// The daemon's own ps output is large; keep the command log entry short.
	result.Output = fmt.Sprintf("%d processes", len(processes))
	daemon, found := fsevents.FindDaemon(processes)
	if !found {
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
// refuses unless fseventsd RSS is at or above the threshold, so a stray call
// cannot restart a healthy daemon and force every FSEvents client to resync.
func restartFSEvents(force bool, rssThresholdBytes int64) ([]CommandResult, error) {
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
	if !force {
		if !before.Found {
			return results, fmt.Errorf("refusing fseventsd restart: process not found; pass --force to kickstart anyway")
		}
		if before.RSSBytes < rssThresholdBytes {
			return results, fmt.Errorf("refusing fseventsd restart: rss %s is below threshold %s; pass --force to override",
				loadprofile.FormatBytes(before.RSSBytes), loadprofile.FormatBytes(rssThresholdBytes))
		}
	}

	result, err = runCoreCommand(launchctlPath, "kickstart", "-k", "system/"+FSEventsLaunchdLabel)
	results = append(results, result)
	if err != nil {
		return results, err
	}

	after, result, err := InspectFSEventsDaemon()
	results = append(results, result)
	if err != nil {
		return results, err
	}
	results = append(results, describeFSEventsState("after", after))
	if after.Found && before.Found && after.PID == before.PID {
		return results, fmt.Errorf("fseventsd pid %d did not change after kickstart", after.PID)
	}
	return results, nil
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
