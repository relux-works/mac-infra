package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// degradedFlag is the exec-degraded flag file contract (sysadmin/docs/host-health-degraded-flag.md).
// Present means: do not start a new heavy lane. Absent means: proceed. Running work is untouched.
type degradedFlag struct {
	Reason       string `json:"reason"`
	Since        string `json:"since"`
	HostWatchPID int    `json:"host_watch_pid"`
}

func writeDegradedFlag(path string, f degradedFlag) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func removeDegradedFlag(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
