package firewall

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	SocketFilterFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"
	Launchctl      = "/bin/launchctl"
	Codesign       = "/usr/bin/codesign"
	Plutil         = "/usr/bin/plutil"
	Lsof           = "/usr/sbin/lsof"
)

// Runner executes one fixed command and returns its combined output. A
// non-zero exit is reported as *ExitError so callers can match exact codes.
type Runner interface {
	Run(ctx context.Context, path string, args ...string) ([]byte, error)
}

type ExitError struct {
	Code int
}

func (e *ExitError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }

func exitCode(err error) int {
	var exit *ExitError
	if errors.As(err, &exit) {
		return exit.Code
	}
	return -1
}

// ServiceSpec is a code-reviewed system service the config may disable.
// Labels never come from a request.
type ServiceSpec struct {
	Name      string `json:"name"`
	Label     string `json:"label"`
	PlistPath string `json:"plist_path"`
}

var serviceAllowlist = []ServiceSpec{
	{Name: "apache", Label: "org.apache.httpd", PlistPath: "/System/Library/LaunchDaemons/org.apache.httpd.plist"},
}

func LookupService(name string) (ServiceSpec, bool) {
	for _, spec := range serviceAllowlist {
		if spec.Name == name {
			return spec, true
		}
	}
	return ServiceSpec{}, false
}

type App struct {
	Name    string `json:"name"`
	Allowed bool   `json:"allowed"`
}

type Service struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Loaded   bool   `json:"loaded"`
	Disabled bool   `json:"disabled"`
}

type State struct {
	Enabled               bool      `json:"enabled"`
	BlockAll              bool      `json:"block_all"`
	Stealth               bool      `json:"stealth"`
	AllowSignedBuiltin    bool      `json:"allow_signed_builtin"`
	AllowSignedDownloaded bool      `json:"allow_signed_downloaded"`
	Apps                  []App     `json:"apps"`
	Services              []Service `json:"services"`
}

// Observe reads the complete managed state. Any unrecognized output is an
// error: planning on a partially understood state could undo the wrong thing.
func Observe(ctx context.Context, r Runner) (State, error) {
	var state State
	out, err := r.Run(ctx, SocketFilterFW, "--getglobalstate")
	if err != nil {
		return State{}, fmt.Errorf("read firewall state: %w", err)
	}
	if state.Enabled, state.BlockAll, err = parseGlobalState(string(out)); err != nil {
		return State{}, err
	}
	if out, err = r.Run(ctx, SocketFilterFW, "--getblockall"); err != nil {
		return State{}, fmt.Errorf("read block-all state: %w", err)
	}
	blockAll, err := parseBlockAll(string(out))
	if err != nil {
		return State{}, err
	}
	state.BlockAll = state.BlockAll || blockAll
	if out, err = r.Run(ctx, SocketFilterFW, "--getstealthmode"); err != nil {
		return State{}, fmt.Errorf("read stealth mode: %w", err)
	}
	if state.Stealth, err = parseStealth(string(out)); err != nil {
		return State{}, err
	}
	if out, err = r.Run(ctx, SocketFilterFW, "--getallowsigned"); err != nil {
		return State{}, fmt.Errorf("read signed-software policy: %w", err)
	}
	if state.AllowSignedBuiltin, state.AllowSignedDownloaded, err = parseAllowSigned(string(out)); err != nil {
		return State{}, err
	}
	if out, err = r.Run(ctx, SocketFilterFW, "--listapps"); err != nil {
		return State{}, fmt.Errorf("list firewall apps: %w", err)
	}
	if state.Apps, err = parseListApps(string(out)); err != nil {
		return State{}, err
	}
	if out, err = r.Run(ctx, Launchctl, "print-disabled", "system"); err != nil {
		return State{}, fmt.Errorf("read disabled services: %w", err)
	}
	overrides, err := parsePrintDisabled(string(out))
	if err != nil {
		return State{}, err
	}
	for _, spec := range serviceAllowlist {
		loaded, err := serviceLoaded(ctx, r, spec.Label)
		if err != nil {
			return State{}, err
		}
		state.Services = append(state.Services, Service{Name: spec.Name, Label: spec.Label, Loaded: loaded, Disabled: overrides[spec.Label]})
	}
	return state, nil
}

func serviceLoaded(ctx context.Context, r Runner, label string) (bool, error) {
	out, err := r.Run(ctx, Launchctl, "print", "system/"+label)
	if err == nil {
		return true, nil
	}
	// Exit 113 alone is insufficient: it must name this exact service.
	missing := fmt.Sprintf("Could not find service %q in domain for system", label)
	text := strings.TrimSpace(string(out))
	if exitCode(err) == 113 && (text == missing || text == "Bad request.\n"+missing) {
		return false, nil
	}
	return false, fmt.Errorf("inspect service %s: %w", label, err)
}

func parseGlobalState(raw string) (enabled, blockAll bool, err error) {
	switch strings.TrimSpace(raw) {
	case "Firewall is disabled. (State = 0)":
		return false, false, nil
	case "Firewall is enabled. (State = 1)":
		return true, false, nil
	case "Firewall is enabled. (State = 2)":
		return true, true, nil
	}
	return false, false, fmt.Errorf("unrecognized firewall state output")
}

var blockAllPattern = regexp.MustCompile(`^Firewall has block all state set to (enabled|disabled)\.$`)

func parseBlockAll(raw string) (bool, error) {
	m := blockAllPattern.FindStringSubmatch(strings.TrimSpace(raw))
	if m == nil {
		return false, fmt.Errorf("unrecognized block-all output")
	}
	return m[1] == "enabled", nil
}

func parseStealth(raw string) (bool, error) {
	switch strings.TrimSpace(raw) {
	case "Firewall stealth mode is on":
		return true, nil
	case "Firewall stealth mode is off":
		return false, nil
	}
	return false, fmt.Errorf("unrecognized stealth mode output")
}

var allowSignedPattern = regexp.MustCompile(`^Automatically allow (built-in|downloaded) signed software (ENABLED|DISABLED)\.$`)

func parseAllowSigned(raw string) (builtin, downloaded bool, err error) {
	lines := nonEmptyLines(raw)
	if len(lines) != 2 {
		return false, false, fmt.Errorf("unrecognized signed-software policy output")
	}
	values := map[string]bool{}
	for _, line := range lines {
		m := allowSignedPattern.FindStringSubmatch(line)
		if m == nil {
			return false, false, fmt.Errorf("unrecognized signed-software policy output")
		}
		values[m[1]] = m[2] == "ENABLED"
	}
	b, okB := values["built-in"]
	d, okD := values["downloaded"]
	if !okB || !okD {
		return false, false, fmt.Errorf("unrecognized signed-software policy output")
	}
	return b, d, nil
}

var (
	appTotalPattern  = regexp.MustCompile(`^Total number of apps = ([0-9]+)$`)
	appEntryPattern  = regexp.MustCompile(`^([0-9]+) : (.+)$`)
	appPolicyPattern = regexp.MustCompile(`^\((Allow|Block) incoming connections\)$`)
)

func parseListApps(raw string) ([]App, error) {
	lines := nonEmptyLines(raw)
	if len(lines) == 0 {
		return nil, fmt.Errorf("unrecognized firewall app list output")
	}
	m := appTotalPattern.FindStringSubmatch(lines[0])
	if m == nil {
		return nil, fmt.Errorf("unrecognized firewall app list output")
	}
	total, err := strconv.Atoi(m[1])
	if err != nil || len(lines) != 1+2*total {
		return nil, fmt.Errorf("firewall app list does not match its declared total")
	}
	apps := make([]App, 0, total)
	for i := 0; i < total; i++ {
		entry := appEntryPattern.FindStringSubmatch(lines[1+2*i])
		policy := appPolicyPattern.FindStringSubmatch(lines[2+2*i])
		if entry == nil || policy == nil || entry[1] != strconv.Itoa(i+1) {
			return nil, fmt.Errorf("unrecognized firewall app list entry %d", i+1)
		}
		apps = append(apps, App{Name: entry[2], Allowed: policy[1] == "Allow"})
	}
	return apps, nil
}

var disabledEntryPattern = regexp.MustCompile(`^"([^"]+)" => (enabled|disabled|true|false)$`)

// parsePrintDisabled reads launchd's persistent overrides. "true" and
// "false" are the older spelling of disabled and enabled.
func parsePrintDisabled(raw string) (map[string]bool, error) {
	lines := nonEmptyLines(raw)
	if len(lines) < 2 || lines[0] != "disabled services = {" {
		return nil, fmt.Errorf("unrecognized launchctl print-disabled output")
	}
	result := map[string]bool{}
	for _, line := range lines[1:] {
		if line == "}" {
			return result, nil
		}
		m := disabledEntryPattern.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("unrecognized launchctl print-disabled entry")
		}
		result[m[1]] = m[2] == "disabled" || m[2] == "true"
	}
	return nil, fmt.Errorf("unterminated launchctl print-disabled output")
}

func nonEmptyLines(raw string) []string {
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

// comparable reduces a state to what rollback must restore. The global
// enabled state is excluded on purpose: the firewall stays on.
func (s State) comparable() string {
	apps := make([]string, 0, len(s.Apps))
	for _, app := range s.Apps {
		apps = append(apps, fmt.Sprintf("%s=%t", app.Name, app.Allowed))
	}
	sort.Strings(apps)
	services := make([]string, 0, len(s.Services))
	for _, service := range s.Services {
		services = append(services, fmt.Sprintf("%s=%t/%t", service.Label, service.Loaded, service.Disabled))
	}
	sort.Strings(services)
	return fmt.Sprintf("block_all=%t stealth=%t signed=%t/%t apps=[%s] services=[%s]",
		s.BlockAll, s.Stealth, s.AllowSignedBuiltin, s.AllowSignedDownloaded,
		strings.Join(apps, ","), strings.Join(services, ","))
}
