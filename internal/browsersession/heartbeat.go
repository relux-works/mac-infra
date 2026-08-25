package browsersession

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultStateDir          = "Library/Application Support/mac-infra/browser-session"
	HeartbeatLabelPrefix     = "works.relux.mac-infra-browser-heartbeat."
	HeartbeatLauncherName    = "mac-browser-heartbeat-launcher"
	minimumHeartbeatInterval = 15 * time.Second
	heartbeatProbeTimeout    = 10 * time.Second
	heartbeatProbeAttempts   = 3
	heartbeatRetryDelay      = 250 * time.Millisecond
	heartbeatStatusGrace     = 5 * time.Second
)

var heartbeatNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,47}$`)

type HeartbeatConfig struct {
	Name       string        `json:"name"`
	Browser    Browser       `json:"browser"`
	WindowID   string        `json:"windowId"`
	TabID      string        `json:"tabId,omitempty"`
	Origin     string        `json:"origin"`
	Interval   time.Duration `json:"interval"`
	Deadline   string        `json:"deadline"`
	Executable string        `json:"executable"`
	Label      string        `json:"label"`
	PlistPath  string        `json:"plistPath"`
	LogPath    string        `json:"logPath"`
	StatePath  string        `json:"statePath"`
	UID        int           `json:"uid"`
}

type HeartbeatOutcome struct {
	Timestamp  string `json:"timestamp"`
	Outcome    string `json:"outcome"`
	Origin     string `json:"origin,omitempty"`
	ReadyState string `json:"readyState,omitempty"`
	ErrorKind  string `json:"errorKind,omitempty"`
}

type HeartbeatStatus struct {
	Name              string  `json:"name"`
	State             string  `json:"state"`
	Browser           Browser `json:"browser,omitempty"`
	WindowID          string  `json:"windowId,omitempty"`
	TabID             string  `json:"tabId,omitempty"`
	Origin            string  `json:"origin,omitempty"`
	ObservedOrigin    string  `json:"observedOrigin,omitempty"`
	Interval          string  `json:"interval,omitempty"`
	Deadline          string  `json:"deadline,omitempty"`
	Expired           bool    `json:"expired"`
	MigrationRequired bool    `json:"migrationRequired,omitempty"`
	Label             string  `json:"label"`
	PlistPath         string  `json:"plistPath"`
	LogPath           string  `json:"logPath"`
	LastOutcome       string  `json:"lastOutcome,omitempty"`
	LastOutcomeAt     string  `json:"lastOutcomeAt,omitempty"`
	ErrorKind         string  `json:"errorKind,omitempty"`
}

type HeartbeatProbe func(context.Context, HeartbeatConfig) (ExecutionResult, error)

type HeartbeatManager struct {
	HomeDir             string
	Launchctl           string
	UID                 int
	Now                 func() time.Time
	RunCommand          func(context.Context, string, ...string) error
	WaitForFirstOutcome func(context.Context, HeartbeatConfig) error
	WaitRetry           func(context.Context, time.Duration) error
}

func NewHeartbeatManager() (HeartbeatManager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return HeartbeatManager{}, fmt.Errorf("resolve user home: %w", err)
	}
	return HeartbeatManager{
		HomeDir:   home,
		Launchctl: "/bin/launchctl",
		UID:       os.Getuid(),
		Now:       time.Now,
	}, nil
}

func (m HeartbeatManager) NewConfig(name string, browser Browser, windowID, tabID, origin string, interval time.Duration, deadline time.Time) (HeartbeatConfig, error) {
	if err := ValidateHeartbeatName(name); err != nil {
		return HeartbeatConfig{}, err
	}
	if browser != BrowserChrome && browser != BrowserSafari {
		return HeartbeatConfig{}, errors.New("heartbeat browser must be chrome or safari")
	}
	if strings.TrimSpace(windowID) == "" || strings.TrimSpace(origin) == "" {
		return HeartbeatConfig{}, errors.New("heartbeat requires window id and expected origin")
	}
	if browser == BrowserChrome && strings.TrimSpace(tabID) == "" {
		return HeartbeatConfig{}, errors.New("Chrome heartbeat requires exact tab id")
	}
	if browser == BrowserSafari && strings.TrimSpace(tabID) != "" {
		return HeartbeatConfig{}, errors.New("Safari heartbeat is window-scoped and does not accept a tab id")
	}
	if interval < minimumHeartbeatInterval {
		return HeartbeatConfig{}, errors.New("heartbeat interval must be at least 15s")
	}
	if deadline.IsZero() || !deadline.After(m.now()) {
		return HeartbeatConfig{}, errors.New("heartbeat deadline must be a finite future time")
	}
	if deadline.Year() < 1 || deadline.Year() > 9999 {
		return HeartbeatConfig{}, errors.New("heartbeat deadline must fit RFC3339")
	}
	paths := m.paths(name)
	return HeartbeatConfig{
		Name:       name,
		Browser:    browser,
		WindowID:   strings.TrimSpace(windowID),
		TabID:      strings.TrimSpace(tabID),
		Origin:     strings.TrimSpace(origin),
		Interval:   interval,
		Deadline:   deadline.UTC().Format(time.RFC3339),
		Executable: m.LauncherPath(),
		Label:      paths.Label,
		PlistPath:  paths.PlistPath,
		LogPath:    paths.LogPath,
		StatePath:  paths.StatePath,
		UID:        m.UID,
	}, nil
}

func (m HeartbeatManager) ResolveDeadline(ttl time.Duration, raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if (ttl > 0) == (raw != "") {
		return time.Time{}, errors.New("heartbeat requires exactly one of a positive --ttl or --deadline")
	}
	if ttl < 0 {
		return time.Time{}, errors.New("heartbeat TTL must be positive")
	}
	var deadline time.Time
	var err error
	if raw != "" {
		deadline, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return time.Time{}, errors.New("heartbeat deadline must be RFC3339")
		}
	} else {
		deadline = m.now().Add(ttl)
	}
	if !deadline.After(m.now()) || deadline.Year() < 1 || deadline.Year() > 9999 {
		return time.Time{}, errors.New("heartbeat deadline must be a finite future time")
	}
	return deadline.UTC(), nil
}

func (m HeartbeatManager) LauncherPath() string {
	return filepath.Join(m.binDir(), HeartbeatLauncherName)
}

func ValidateHeartbeatName(name string) error {
	if !heartbeatNamePattern.MatchString(name) {
		return errors.New("heartbeat name must match [a-z0-9][a-z0-9-]{0,47}")
	}
	return nil
}

func HeartbeatJavaScript() string {
	return `(() => {
  const target = document.querySelector("textarea,input,[contenteditable=true]") || document.body || document.documentElement;
  target.dispatchEvent(new MouseEvent("mousemove", {bubbles:true,clientX:1,clientY:1}));
  target.dispatchEvent(new PointerEvent("pointermove", {bubbles:true,clientX:1,clientY:1}));
  target.dispatchEvent(new KeyboardEvent("keydown", {bubbles:true,key:"Shift",code:"ShiftLeft"}));
  target.dispatchEvent(new KeyboardEvent("keyup", {bubbles:true,key:"Shift",code:"ShiftLeft"}));
  return JSON.stringify({ok:true,origin:location.origin,readyState:document.readyState});
})()`
}

func (m HeartbeatManager) Start(ctx context.Context, cfg HeartbeatConfig, preflight HeartbeatProbe) (HeartbeatConfig, error) {
	if preflight == nil {
		return HeartbeatConfig{}, errors.New("heartbeat preflight is required")
	}
	if err := m.validateConfig(cfg); err != nil {
		return HeartbeatConfig{}, err
	}
	if err := validateInstalledHeartbeatLauncher(cfg.Executable); err != nil {
		return HeartbeatConfig{}, err
	}
	if _, err := os.Stat(cfg.StatePath); err == nil {
		return HeartbeatConfig{}, fmt.Errorf("heartbeat %q is already configured; stop it before replacing its target", cfg.Name)
	} else if !os.IsNotExist(err) {
		return HeartbeatConfig{}, fmt.Errorf("inspect heartbeat state: %w", err)
	}
	if _, err := os.Stat(cfg.PlistPath); err == nil {
		return HeartbeatConfig{}, fmt.Errorf("heartbeat %q has an orphaned LaunchAgent; stop it before starting", cfg.Name)
	} else if !os.IsNotExist(err) {
		return HeartbeatConfig{}, fmt.Errorf("inspect heartbeat LaunchAgent: %w", err)
	}
	if _, err := preflight(ctx, cfg); err != nil {
		return HeartbeatConfig{}, fmt.Errorf("heartbeat preflight: %w", err)
	}
	plist, err := RenderHeartbeatLaunchAgent(cfg)
	if err != nil {
		return HeartbeatConfig{}, err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.StatePath), 0o700); err != nil {
		return HeartbeatConfig{}, err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.PlistPath), 0o700); err != nil {
		return HeartbeatConfig{}, err
	}
	if err := os.WriteFile(cfg.LogPath, nil, 0o600); err != nil {
		return HeartbeatConfig{}, err
	}
	if err := os.Chmod(cfg.LogPath, 0o600); err != nil {
		return HeartbeatConfig{}, err
	}
	state, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return HeartbeatConfig{}, err
	}
	if err := writeAtomic(cfg.StatePath, append(state, '\n'), 0o600); err != nil {
		return HeartbeatConfig{}, err
	}
	if err := writeAtomic(cfg.PlistPath, plist, 0o600); err != nil {
		_ = os.Remove(cfg.StatePath)
		return HeartbeatConfig{}, err
	}
	if err := m.runLaunchctl(ctx, "bootstrap", "gui/"+strconv.Itoa(cfg.UID), cfg.PlistPath); err != nil {
		_ = os.Remove(cfg.PlistPath)
		_ = os.Remove(cfg.StatePath)
		_ = os.Remove(cfg.LogPath)
		return HeartbeatConfig{}, err
	}
	if err := m.waitForFirstBackgroundOutcome(ctx, cfg); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if cleanupErr := m.Stop(cleanupCtx, cfg.Name); cleanupErr != nil {
			return HeartbeatConfig{}, fmt.Errorf("heartbeat background preflight: %w; cleanup failed: %v", err, cleanupErr)
		}
		return HeartbeatConfig{}, fmt.Errorf("heartbeat background preflight: %w", err)
	}
	return cfg, nil
}

func (m HeartbeatManager) Restart(ctx context.Context, name string, deadline time.Time, preflight HeartbeatProbe) (HeartbeatConfig, error) {
	if preflight == nil {
		return HeartbeatConfig{}, errors.New("heartbeat preflight is required")
	}
	current, _, err := m.loadStored(name)
	if err != nil {
		return HeartbeatConfig{}, err
	}
	replacement, err := m.NewConfig(current.Name, current.Browser, current.WindowID, current.TabID, current.Origin, current.Interval, deadline)
	if err != nil {
		return HeartbeatConfig{}, err
	}
	if err := validateInstalledHeartbeatLauncher(replacement.Executable); err != nil {
		return HeartbeatConfig{}, err
	}
	if _, err := preflight(ctx, replacement); err != nil {
		return HeartbeatConfig{}, fmt.Errorf("heartbeat restart preflight: %w", err)
	}
	if err := m.Stop(ctx, name); err != nil {
		return HeartbeatConfig{}, fmt.Errorf("stop heartbeat before restart: %w", err)
	}
	return m.Start(ctx, replacement, preflight)
}

func (m HeartbeatManager) waitForFirstBackgroundOutcome(ctx context.Context, cfg HeartbeatConfig) error {
	if m.WaitForFirstOutcome != nil {
		return m.WaitForFirstOutcome(ctx, cfg)
	}
	for {
		outcome, ok, err := readLastHeartbeatOutcome(cfg.LogPath)
		if err != nil {
			return err
		}
		if ok {
			switch {
			case outcome.Outcome == "ok":
				return nil
			case outcome.Outcome == "refused":
				return &OriginMismatchError{Expected: cfg.Origin, Observed: outcome.Origin}
			case outcome.ErrorKind == "target-missing":
				return &TargetMissingError{Browser: cfg.Browser, Target: heartbeatTarget(cfg), Detail: "target disappeared during background preflight"}
			case outcome.ErrorKind != "":
				return fmt.Errorf("background heartbeat outcome: %s", outcome.ErrorKind)
			default:
				return errors.New("background heartbeat returned an unreadable outcome")
			}
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func heartbeatTarget(cfg HeartbeatConfig) string {
	if cfg.TabID == "" {
		return cfg.WindowID
	}
	return cfg.WindowID + "/" + cfg.TabID
}

func (m HeartbeatManager) Stop(ctx context.Context, name string) error {
	if err := ValidateHeartbeatName(name); err != nil {
		return err
	}
	paths := m.paths(name)
	cfg, _, err := m.loadStored(name)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	uid := m.UID
	if err == nil {
		uid = cfg.UID
	}
	service := "gui/" + strconv.Itoa(uid) + "/" + paths.Label
	if launchErr := m.runLaunchctl(ctx, "bootout", service); launchErr != nil && !isMissingLaunchAgent(launchErr) {
		return launchErr
	}
	for _, path := range []string{paths.PlistPath, paths.StatePath, paths.LogPath} {
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return removeErr
		}
	}
	return m.GarbageCollectExecutables()
}

func (m HeartbeatManager) expire(ctx context.Context, cfg HeartbeatConfig) error {
	// Remove the restart inputs before booting out the job. launchctl may kill
	// this process during bootout, but it cannot relaunch without the plist/state.
	for _, path := range []string{cfg.PlistPath, cfg.StatePath, cfg.LogPath} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	service := "gui/" + strconv.Itoa(cfg.UID) + "/" + cfg.Label
	if err := m.runLaunchctl(ctx, "bootout", service); err != nil && !isMissingLaunchAgent(err) {
		return err
	}
	return m.GarbageCollectExecutables()
}

func (m HeartbeatManager) StopAll(ctx context.Context) error {
	names, err := m.ConfiguredNames()
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := m.Stop(ctx, name); err != nil {
			return fmt.Errorf("stop heartbeat %q: %w", name, err)
		}
	}
	return m.GarbageCollectExecutables()
}

func (m HeartbeatManager) Inspect(ctx context.Context, name string) (HeartbeatStatus, error) {
	if err := ValidateHeartbeatName(name); err != nil {
		return HeartbeatStatus{}, err
	}
	paths := m.paths(name)
	status := HeartbeatStatus{Name: name, State: "not-configured", Label: paths.Label, PlistPath: paths.PlistPath, LogPath: paths.LogPath}
	cfg, migrationRequired, err := m.loadStored(name)
	if err != nil {
		if os.IsNotExist(err) {
			return status, nil
		}
		return HeartbeatStatus{}, err
	}
	status.Browser = cfg.Browser
	status.WindowID = cfg.WindowID
	status.TabID = cfg.TabID
	status.Origin = cfg.Origin
	status.Interval = cfg.Interval.String()
	status.Deadline = cfg.Deadline
	status.MigrationRequired = migrationRequired
	if cfg.Deadline == "" {
		status.State = "migration-required"
		status.ErrorKind = "missing-deadline"
		return status, nil
	}
	deadline, err := heartbeatDeadline(cfg)
	if err != nil {
		return HeartbeatStatus{}, err
	}
	if !m.now().Before(deadline) {
		status.State = "expired"
		status.Expired = true
		status.ErrorKind = "deadline-expired"
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := m.expire(cleanupCtx, cfg); err != nil {
			return HeartbeatStatus{}, fmt.Errorf("clean expired heartbeat %q: %w", name, err)
		}
		return status, nil
	}
	if migrationRequired {
		status.State = "migration-required"
		status.ErrorKind = "legacy-launcher"
		return status, nil
	}
	service := "gui/" + strconv.Itoa(cfg.UID) + "/" + cfg.Label
	if err := m.runLaunchctl(ctx, "print", service); err != nil {
		if isMissingLaunchAgent(err) {
			status.State = "configured-not-loaded"
			return status, nil
		}
		status.State = "unknown"
		return status, nil
	}
	last, ok, err := readLastHeartbeatOutcome(cfg.LogPath)
	if err != nil {
		status.State = "unknown"
		return status, nil
	}
	if !ok {
		status.State = "unavailable"
		return status, nil
	}
	status.LastOutcome = last.Outcome
	status.LastOutcomeAt = last.Timestamp
	status.ErrorKind = last.ErrorKind
	if last.Outcome == "ok" {
		if heartbeatOutcomeIsFresh(m.now(), cfg.Interval, last.Timestamp) {
			status.State = "running"
		} else {
			status.State = "unavailable"
			status.ErrorKind = "stale-outcome"
		}
		return status, nil
	}
	status.ObservedOrigin = last.Origin
	switch {
	case last.Outcome == "refused":
		status.State = "drifted"
	case last.ErrorKind == "target-missing":
		status.State = "target-missing"
	default:
		status.State = "unavailable"
	}
	return status, nil
}

func (m HeartbeatManager) List(ctx context.Context) ([]HeartbeatStatus, error) {
	names, err := m.ConfiguredNames()
	if err != nil {
		return nil, err
	}
	statuses := make([]HeartbeatStatus, 0, len(names))
	for _, name := range names {
		status, err := m.Inspect(ctx, name)
		if err != nil {
			return nil, err
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

func (m HeartbeatManager) Run(ctx context.Context, name string, probe HeartbeatProbe) error {
	if err := ValidateHeartbeatName(name); err != nil {
		return err
	}
	if probe == nil {
		return errors.New("heartbeat probe is required")
	}
	for {
		cfg, err := m.Load(name)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		deadline, err := heartbeatDeadline(cfg)
		if err != nil {
			return err
		}
		if !m.now().Before(deadline) {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			return m.expire(cleanupCtx, cfg)
		}
		runCtx, cancelRun := context.WithTimeout(ctx, deadline.Sub(m.now()))
		started := m.now().UTC()
		probeStarted := time.Now()
		result, probeErr := m.runProbeWithRetry(runCtx, cfg, probe)
		cancelRun()
		if !m.now().Before(deadline) || (errors.Is(runCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil) {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			return m.expire(cleanupCtx, cfg)
		}
		outcome := HeartbeatOutcome{Timestamp: started.Format(time.RFC3339), Outcome: "ok", Origin: result.Origin, ReadyState: result.ReadyState}
		if probeErr != nil {
			outcome.Origin = ""
			outcome.ReadyState = ""
			var mismatch *OriginMismatchError
			switch {
			case errors.As(probeErr, &mismatch):
				outcome.Outcome = "refused"
				outcome.Origin = mismatch.Observed
			case errors.Is(probeErr, ErrTargetMissing):
				outcome.Outcome = "error"
				outcome.ErrorKind = "target-missing"
			default:
				outcome.Outcome = "error"
				outcome.ErrorKind = heartbeatErrorKind(probeErr)
			}
		}
		if err := appendHeartbeatOutcome(cfg.LogPath, outcome); err != nil {
			return err
		}
		delay := cfg.Interval - time.Since(probeStarted)
		if delay < 0 {
			delay = 0
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-time.After(deadline.Sub(m.now())):
			timer.Stop()
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			return m.expire(cleanupCtx, cfg)
		case <-timer.C:
		}
	}
}

func (m HeartbeatManager) runProbeWithRetry(ctx context.Context, cfg HeartbeatConfig, probe HeartbeatProbe) (ExecutionResult, error) {
	var lastErr error
	for attempt := 1; attempt <= heartbeatProbeAttempts; attempt++ {
		probeCtx, cancel := context.WithTimeout(ctx, heartbeatProbeTimeout)
		result, err := probe(probeCtx, cfg)
		cancel()
		if err == nil {
			return result, nil
		}
		lastErr = err
		if attempt == heartbeatProbeAttempts || !heartbeatProbeRetryable(err) {
			break
		}
		if err := m.waitRetry(ctx, time.Duration(attempt)*heartbeatRetryDelay); err != nil {
			return ExecutionResult{}, err
		}
	}
	return ExecutionResult{}, lastErr
}

func heartbeatProbeRetryable(err error) bool {
	var mismatch *OriginMismatchError
	return !errors.As(err, &mismatch) &&
		!errors.Is(err, ErrTargetMissing) &&
		!errors.Is(err, ErrSensitiveJavaScript) &&
		heartbeatErrorKind(err) != "automation-disabled"
}

func (m HeartbeatManager) waitRetry(ctx context.Context, delay time.Duration) error {
	if m.WaitRetry != nil {
		return m.WaitRetry(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func heartbeatErrorKind(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, ErrUnreadableResponse):
		return "unreadable-response"
	case errors.Is(err, ErrSensitiveJavaScript):
		return "guard-refusal"
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "javascript") && (strings.Contains(lower, "apple events") || strings.Contains(lower, "applescript") || strings.Contains(lower, "not allowed") || strings.Contains(lower, "turned off")) {
		return "automation-disabled"
	}
	if strings.Contains(lower, "signal: killed") || strings.Contains(lower, "timed out") || strings.Contains(lower, "deadline exceeded") {
		return "timeout"
	}
	return "unavailable"
}

func heartbeatOutcomeIsFresh(now time.Time, interval time.Duration, timestamp string) bool {
	observed, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return false
	}
	maximumAge := interval + time.Duration(heartbeatProbeAttempts)*heartbeatProbeTimeout +
		time.Duration(heartbeatProbeAttempts-1)*heartbeatRetryDelay + heartbeatStatusGrace
	age := now.UTC().Sub(observed)
	return age >= 0 && age <= maximumAge
}

func (m HeartbeatManager) Load(name string) (HeartbeatConfig, error) {
	cfg, migrationRequired, err := m.loadStored(name)
	if err != nil {
		return HeartbeatConfig{}, err
	}
	if migrationRequired {
		return HeartbeatConfig{}, fmt.Errorf("heartbeat %q requires restart with a deadline and the stable launcher", name)
	}
	return cfg, nil
}

func (m HeartbeatManager) loadStored(name string) (HeartbeatConfig, bool, error) {
	if err := ValidateHeartbeatName(name); err != nil {
		return HeartbeatConfig{}, false, err
	}
	data, err := os.ReadFile(m.paths(name).StatePath)
	if err != nil {
		return HeartbeatConfig{}, false, err
	}
	var cfg HeartbeatConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return HeartbeatConfig{}, false, fmt.Errorf("decode heartbeat state %q: %w", name, err)
	}
	migrationRequired, err := m.validateStoredConfig(cfg)
	if err != nil {
		return HeartbeatConfig{}, false, fmt.Errorf("validate heartbeat state %q: %w", name, err)
	}
	return cfg, migrationRequired, nil
}

func (m HeartbeatManager) ConfiguredNames() ([]string, error) {
	entries, err := os.ReadDir(m.stateDir())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		if err := ValidateHeartbeatName(name); err != nil {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func (m HeartbeatManager) GarbageCollectExecutables() error {
	names, err := m.ConfiguredNames()
	if err != nil {
		return err
	}
	referenced := make(map[string]bool, len(names))
	for _, name := range names {
		cfg, _, err := m.loadStored(name)
		if err != nil {
			return err
		}
		referenced[filepath.Clean(cfg.Executable)] = true
	}
	entries, err := os.ReadDir(m.binDir())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "mac-browser-session-") {
			continue
		}
		path := filepath.Join(m.binDir(), entry.Name())
		if !referenced[filepath.Clean(path)] {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}

func RenderHeartbeatLaunchAgent(cfg HeartbeatConfig) ([]byte, error) {
	managedBin := filepath.Join(filepath.Dir(cfg.StatePath), "bin")
	cleanExecutable := filepath.Clean(cfg.Executable)
	if cleanExecutable != filepath.Join(filepath.Clean(managedBin), HeartbeatLauncherName) {
		return nil, errors.New("heartbeat LaunchAgent executable must be the stable installed launcher")
	}
	args := []string{cleanExecutable, "heartbeat", "run", "--name", cfg.Name}
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n")
	b.WriteString("  <key>Label</key><string>" + xmlEscape(cfg.Label) + "</string>\n  <key>ProgramArguments</key><array>\n")
	for _, arg := range args {
		b.WriteString("    <string>" + xmlEscape(arg) + "</string>\n")
	}
	b.WriteString("  </array>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n  <key>Umask</key><integer>63</integer>\n")
	b.WriteString("  <key>StandardOutPath</key><string>/dev/null</string>\n  <key>StandardErrorPath</key><string>/dev/null</string>\n</dict>\n</plist>\n")
	return []byte(b.String()), nil
}

func (m HeartbeatManager) validateConfig(cfg HeartbeatConfig) error {
	migrationRequired, err := m.validateStoredConfig(cfg)
	if err != nil {
		return err
	}
	if migrationRequired {
		return errors.New("heartbeat state requires restart with a deadline and the stable launcher")
	}
	return nil
}

func (m HeartbeatManager) validateStoredConfig(cfg HeartbeatConfig) (bool, error) {
	if err := ValidateHeartbeatName(cfg.Name); err != nil {
		return false, err
	}
	paths := m.paths(cfg.Name)
	if cfg.Label != paths.Label || filepath.Clean(cfg.PlistPath) != filepath.Clean(paths.PlistPath) || filepath.Clean(cfg.LogPath) != filepath.Clean(paths.LogPath) || filepath.Clean(cfg.StatePath) != filepath.Clean(paths.StatePath) {
		return false, errors.New("heartbeat state paths do not match managed namespace")
	}
	if cfg.UID != m.UID {
		return false, errors.New("heartbeat state uid does not match current user")
	}
	if cfg.Browser != BrowserChrome && cfg.Browser != BrowserSafari {
		return false, errors.New("heartbeat state has unsupported browser")
	}
	if cfg.WindowID == "" || cfg.Origin == "" || cfg.Interval < minimumHeartbeatInterval {
		return false, errors.New("heartbeat state is incomplete")
	}
	if cfg.Browser == BrowserChrome && cfg.TabID == "" {
		return false, errors.New("Chrome heartbeat state has no tab id")
	}
	if cfg.Browser == BrowserSafari && cfg.TabID != "" {
		return false, errors.New("Safari heartbeat state unexpectedly has a tab id")
	}
	cleanExecutable := filepath.Clean(cfg.Executable)
	stableLauncher := filepath.Clean(m.LauncherPath())
	legacyLauncher := filepath.Dir(cleanExecutable) == filepath.Clean(m.binDir()) && strings.HasPrefix(filepath.Base(cleanExecutable), "mac-browser-session-")
	if cleanExecutable != stableLauncher && !legacyLauncher {
		return false, errors.New("heartbeat state executable is outside the managed launcher namespace")
	}
	migrationRequired := legacyLauncher || cfg.Deadline == ""
	if cfg.Deadline != "" {
		if _, err := heartbeatDeadline(cfg); err != nil {
			return false, err
		}
	}
	return migrationRequired, nil
}

func heartbeatDeadline(cfg HeartbeatConfig) (time.Time, error) {
	deadline, err := time.Parse(time.RFC3339, cfg.Deadline)
	if err != nil {
		return time.Time{}, errors.New("heartbeat state has invalid deadline")
	}
	return deadline.UTC(), nil
}

func validateInstalledHeartbeatLauncher(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect stable heartbeat launcher: %w; rerun scripts/setup.sh", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("stable heartbeat launcher is not an executable regular file; rerun scripts/setup.sh")
	}
	return nil
}

func (m HeartbeatManager) runLaunchctl(ctx context.Context, args ...string) error {
	path := m.Launchctl
	if strings.TrimSpace(path) == "" {
		path = "/bin/launchctl"
	}
	if m.RunCommand != nil {
		return m.RunCommand(ctx, path, args...)
	}
	cmd := exec.CommandContext(ctx, path, args...)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		exitCode := -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		verb := ""
		if len(args) > 0 {
			verb = args[0]
		}
		return &launchctlCommandError{
			args:     append([]string(nil), args...),
			verb:     verb,
			exitCode: exitCode,
			output:   strings.TrimSpace(output.String()),
			cause:    err,
		}
	}
	return nil
}

type launchctlCommandError struct {
	args     []string
	verb     string
	exitCode int
	output   string
	cause    error
}

func (e *launchctlCommandError) Error() string {
	detail := e.output
	if detail == "" && e.cause != nil {
		detail = e.cause.Error()
	}
	return fmt.Sprintf("launchctl %s: %s", strings.Join(e.args, " "), detail)
}

func (e *launchctlCommandError) Unwrap() error {
	return e.cause
}

type heartbeatPaths struct {
	Label     string
	PlistPath string
	LogPath   string
	StatePath string
}

func (m HeartbeatManager) paths(name string) heartbeatPaths {
	label := HeartbeatLabelPrefix + name
	return heartbeatPaths{
		Label:     label,
		PlistPath: filepath.Join(m.HomeDir, "Library", "LaunchAgents", label+".plist"),
		LogPath:   filepath.Join(m.stateDir(), name+".log"),
		StatePath: filepath.Join(m.stateDir(), name+".json"),
	}
}

func (m HeartbeatManager) stateDir() string { return filepath.Join(m.HomeDir, DefaultStateDir) }
func (m HeartbeatManager) binDir() string   { return filepath.Join(m.stateDir(), "bin") }

func (m HeartbeatManager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func appendHeartbeatOutcome(path string, outcome HeartbeatOutcome) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	data, err := json.Marshal(outcome)
	if err != nil {
		return err
	}
	_, err = file.Write(append(data, '\n'))
	return err
}

func readLastHeartbeatOutcome(path string) (HeartbeatOutcome, bool, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return HeartbeatOutcome{}, false, nil
	}
	if err != nil {
		return HeartbeatOutcome{}, false, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var last string
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			last = scanner.Text()
		}
	}
	if err := scanner.Err(); err != nil {
		return HeartbeatOutcome{}, false, err
	}
	if last == "" {
		return HeartbeatOutcome{}, false, nil
	}
	var outcome HeartbeatOutcome
	if err := json.Unmarshal([]byte(last), &outcome); err != nil {
		return HeartbeatOutcome{}, false, err
	}
	if outcome.Outcome != "ok" && outcome.Outcome != "refused" && outcome.Outcome != "error" {
		return HeartbeatOutcome{}, false, errors.New("invalid heartbeat outcome")
	}
	return outcome, true, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func isMissingLaunchAgent(err error) bool {
	var commandErr *launchctlCommandError
	if errors.As(err, &commandErr) {
		output := strings.ToLower(strings.TrimSpace(commandErr.output))
		switch commandErr.verb {
		case "print":
			return commandErr.exitCode == 113 && containsLineWithPrefix(output, "could not find service \"")
		case "bootout":
			return commandErr.exitCode == 3 && containsExactLine(output, "boot-out failed: 3: no such process")
		default:
			return false
		}
	}

	// RunCommand is a test/integration hook without structured process status.
	// Admit only complete known sentinel messages; never search composed command
	// text where a valid service label or UID can supply misleading digits.
	text := strings.ToLower(strings.TrimSpace(err.Error()))
	return text == "could not find service" || text == "service not found" || text == "no such process"
}

func containsLineWithPrefix(text, prefix string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			return true
		}
	}
	return false
}

func containsExactLine(text, expected string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == expected {
			return true
		}
	}
	return false
}

func xmlEscape(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&apos;")
	return replacer.Replace(value)
}
