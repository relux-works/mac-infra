// Package security provides bounded, read-only macOS audit collectors. Unknown
// or inaccessible evidence is coverage loss, never evidence of a clean host.
package security

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type Finding struct {
	Check    string `json:"check"`
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Detail   string `json:"detail"`
}
type Check struct {
	StartedAt    time.Time         `json:"started_at"`
	FinishedAt   time.Time         `json:"finished_at"`
	Commands     []CommandEvidence `json:"commands"`
	Name         string            `json:"name"`
	Status       string            `json:"status"`
	RequiresRoot bool              `json:"requires_root,omitempty"`
	Findings     []Finding         `json:"findings"`
	Data         map[string]any    `json:"data,omitempty"`
}
type Report struct {
	Schema      int       `json:"schema"`
	GeneratedAt time.Time `json:"generated_at"`
	Checks      []Check   `json:"checks"`
	Persistence Snapshot  `json:"persistence"`
}

// CommandRunner never invokes a shell or sudo. Each command has a deadline and
// bounded output; stderr is discarded because it may contain host secrets.
type CommandRunner struct {
	Timeout   time.Duration
	MaxOutput int
}

var ErrOutputLimit = errors.New("command output limit reached")

type limitedBuffer struct {
	mu       sync.Mutex
	data     []byte
	max      int
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(p) > b.max-len(b.data) {
		b.exceeded = true
		b.data = append(b.data, p[:b.max-len(b.data)]...)
		return len(p), nil
	}
	b.data = append(b.data, p...)
	return len(p), nil
}
func (r CommandRunner) Run(ctx context.Context, path string, args ...string) ([]byte, error) {
	if !allowedCommand(path, args) {
		return nil, errors.New("command not allowed")
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	max := r.MaxOutput
	if max <= 0 {
		max = 2 << 20
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	b := &limitedBuffer{max: max}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout = b
	cmd.Stderr = io.Discard
	cmd.Stdin = nil
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if b.exceeded {
		return nil, ErrOutputLimit
	}
	return b.data, err
}

// A fixed read-only command vocabulary prevents a future collector accidentally
// turning the auditing runner into a general execution or configuration API.
func allowedCommand(path string, args []string) bool {
	key := path + " " + strings.Join(args, " ")
	switch key {
	case "/usr/sbin/lsof -nP -i -Fpn", "/usr/sbin/lsof -nP -iTCP -sTCP:LISTEN -Ts -F pufPnT", "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate", "/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode", "/sbin/pfctl -s info", "/usr/bin/csrutil status", "/usr/sbin/spctl --status", "/usr/bin/fdesetup status", "/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled", "/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload", "/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall", "/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall", "/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates", "/usr/bin/defaults read /Library/Preferences/com.apple.commerce AutoUpdate", "/usr/bin/defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info CFBundleShortVersionString", "/usr/bin/profiles list -output stdout-xml", "/usr/bin/systemextensionsctl list", "/usr/bin/sfltool dumpbtm", "/usr/bin/crontab -l", "/usr/sbin/systemsetup -getremotelogin", "/usr/sbin/systemsetup -getremoteappleevents", "/bin/launchctl print-disabled system", "/usr/bin/ssh-add -l":
		return true
	}
	return false
}
func unavailable(name string, root bool, code string) Check {
	return Check{Name: name, Status: "unavailable", RequiresRoot: root, Findings: []Finding{{name, "info", code, "Evidence unavailable; this check does not establish a clean state."}}}
}
func finding(check, severity, code, detail string) Finding {
	return Finding{check, severity, code, detail}
}
func Summary(r Report) string {
	counts := map[string]int{}
	partial := 0
	for _, c := range r.Checks {
		if c.Status != "ok" {
			partial++
		}
		for _, f := range c.Findings {
			counts[f.Severity]++
		}
	}
	return fmt.Sprintf("mac-security: %d checks, %d incomplete; %d critical, %d warning findings. Read-only point-in-time evidence; no clean-host verdict.", len(r.Checks), partial, counts["critical"], counts["warning"])
}
