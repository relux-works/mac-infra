package firewall

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	StepGlobalOn              = "global_on"
	StepStealth               = "stealth"
	StepBlockAll              = "block_all"
	StepAllowSignedBuiltin    = "allow_signed_builtin"
	StepAllowSignedDownloaded = "allow_signed_downloaded"
	StepAppAddAllow           = "app_add_allow"
	StepAppAddBlock           = "app_add_block"
	StepAppAllow              = "app_allow"
	StepAppBlock              = "app_block"
	StepAppRemove             = "app_remove"
	StepServiceDisable        = "service_disable"
	StepServiceStop           = "service_stop"
)

// Step is one reversible change. Argv and Undo hold fixed command lines
// built from the allowlisted tools; nothing in them is a shell string.
type Step struct {
	Kind     string       `json:"kind"`
	Target   string       `json:"target,omitempty"`
	Value    string       `json:"value,omitempty"`
	Loosens  bool         `json:"loosens"`
	Argv     [][]string   `json:"argv"`
	Undo     [][]string   `json:"undo,omitempty"`
	Identity *AppIdentity `json:"identity,omitempty"`
}

type Plan struct {
	Steps []Step `json:"steps"`
	// Unmanaged lists exact-mode entries that socketfilterfw reports by
	// bundle id; they cannot be addressed by path and are left untouched.
	Unmanaged []string `json:"unmanaged,omitempty"`
}

type AppIdentity struct {
	Identifier string `json:"identifier,omitempty"`
	TeamID     string `json:"team_id,omitempty"`
}

// Resolver supplies the host facts planning depends on.
type Resolver interface {
	// Aliases returns every name socketfilterfw may list the app under.
	Aliases(ctx context.Context, path string) ([]string, error)
	// VerifySigned requires a valid signature anchored to Apple's CA
	// (Apple, App Store or Developer ID). Ad-hoc and unsigned code fail.
	VerifySigned(ctx context.Context, path string) (AppIdentity, error)
}

// BuildPlan computes the steps from current to desired. With verify set,
// every loosening app step must pass VerifySigned; any failure returns an
// error before a single mutation can run.
func BuildPlan(ctx context.Context, cfg Config, current State, resolver Resolver, verify bool) (Plan, error) {
	if err := cfg.Validate(); err != nil {
		return Plan{}, err
	}
	plan := Plan{Steps: []Step{}}
	if !current.Enabled {
		plan.Steps = append(plan.Steps, Step{Kind: StepGlobalOn, Value: "on", Argv: [][]string{fw("--setglobalstate", "on")}})
	}
	toggle := func(kind string, want *bool, have bool, flag string, loosensWhen bool) {
		if want == nil || *want == have {
			return
		}
		plan.Steps = append(plan.Steps, Step{
			Kind: kind, Value: onOff(*want), Loosens: *want == loosensWhen,
			Argv: [][]string{fw(flag, onOff(*want))}, Undo: [][]string{fw(flag, onOff(have))},
		})
	}
	toggle(StepBlockAll, cfg.BlockAll, current.BlockAll, "--setblockall", false)
	toggle(StepStealth, cfg.Stealth, current.Stealth, "--setstealthmode", false)
	toggle(StepAllowSignedBuiltin, cfg.AllowSignedBuiltin, current.AllowSignedBuiltin, "--setallowsigned", true)
	toggle(StepAllowSignedDownloaded, cfg.AllowSignedDownloaded, current.AllowSignedDownloaded, "--setallowsignedapp", true)

	matched := make([]bool, len(current.Apps))
	for _, entry := range append(appWants(cfg.Apps.Allow, true), appWants(cfg.Apps.Block, false)...) {
		if err := requireExistingPath(entry.path); err != nil {
			return Plan{}, err
		}
		aliases, err := resolver.Aliases(ctx, entry.path)
		if err != nil {
			return Plan{}, fmt.Errorf("resolve %s: %w", entry.path, err)
		}
		index := findApp(current.Apps, aliases)
		step, ok := appStep(entry, index, current.Apps)
		if index >= 0 {
			if matched[index] {
				return Plan{}, fmt.Errorf("%s matches a firewall entry already claimed by another config path", entry.path)
			}
			matched[index] = true
		}
		if !ok {
			continue
		}
		if step.Loosens && verify {
			identity, err := resolver.VerifySigned(ctx, entry.path)
			if err != nil {
				return Plan{}, fmt.Errorf("refusing to allow %s: %w", entry.path, err)
			}
			step.Identity = &identity
		}
		plan.Steps = append(plan.Steps, step)
	}
	if cfg.Apps.Mode == ModeExact {
		for index, app := range current.Apps {
			if matched[index] {
				continue
			}
			if !filepath.IsAbs(app.Name) {
				plan.Unmanaged = append(plan.Unmanaged, app.Name)
				continue
			}
			undo := [][]string{fw("--add", app.Name)}
			if !app.Allowed {
				undo = append(undo, fw("--blockapp", app.Name))
			}
			plan.Steps = append(plan.Steps, Step{Kind: StepAppRemove, Target: app.Name, Loosens: !app.Allowed, Argv: [][]string{fw("--remove", app.Name)}, Undo: undo})
		}
	}

	for _, name := range cfg.Services.Disable {
		spec, _ := LookupService(name)
		var service Service
		for _, observed := range current.Services {
			if observed.Label == spec.Label {
				service = observed
			}
		}
		if service.Label == "" {
			return Plan{}, fmt.Errorf("service %s was not observed", spec.Label)
		}
		target := "system/" + spec.Label
		if !service.Disabled {
			plan.Steps = append(plan.Steps, Step{Kind: StepServiceDisable, Target: spec.Label,
				Argv: [][]string{{Launchctl, "disable", target}}, Undo: [][]string{{Launchctl, "enable", target}}})
		}
		if service.Loaded {
			plan.Steps = append(plan.Steps, Step{Kind: StepServiceStop, Target: spec.Label,
				Argv: [][]string{{Launchctl, "bootout", target}}, Undo: [][]string{{Launchctl, "bootstrap", "system", spec.PlistPath}}})
		}
	}
	return plan, nil
}

type appWant struct {
	path  string
	allow bool
}

func appWants(paths []string, allow bool) []appWant {
	wants := make([]appWant, 0, len(paths))
	for _, path := range paths {
		wants = append(wants, appWant{path: path, allow: allow})
	}
	return wants
}

func appStep(want appWant, index int, apps []App) (Step, bool) {
	path := want.path
	switch {
	case index < 0 && want.allow:
		return Step{Kind: StepAppAddAllow, Target: path, Loosens: true, Argv: [][]string{fw("--add", path), fw("--unblockapp", path)}, Undo: [][]string{fw("--remove", path)}}, true
	case index < 0:
		return Step{Kind: StepAppAddBlock, Target: path, Argv: [][]string{fw("--add", path), fw("--blockapp", path)}, Undo: [][]string{fw("--remove", path)}}, true
	case want.allow && !apps[index].Allowed:
		return Step{Kind: StepAppAllow, Target: path, Loosens: true, Argv: [][]string{fw("--unblockapp", path)}, Undo: [][]string{fw("--blockapp", path)}}, true
	case !want.allow && apps[index].Allowed:
		return Step{Kind: StepAppBlock, Target: path, Argv: [][]string{fw("--blockapp", path)}, Undo: [][]string{fw("--unblockapp", path)}}, true
	}
	return Step{}, false
}

func findApp(apps []App, aliases []string) int {
	for index, app := range apps {
		for _, alias := range aliases {
			if app.Name == alias {
				return index
			}
		}
	}
	return -1
}

// requireExistingPath refuses missing paths and symlinks: socketfilterfw
// would record whatever the link pointed to at the time of the change.
func requireExistingPath(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("app path %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("app path %s is a symlink; list the target path instead", path)
	}
	return nil
}

func fw(args ...string) []string {
	return append([]string{SocketFilterFW}, args...)
}

func onOff(value bool) string {
	if value {
		return "on"
	}
	return "off"
}

// SystemResolver answers resolver queries with fixed system tools.
type SystemResolver struct {
	Runner Runner
}

func (s SystemResolver) Aliases(ctx context.Context, path string) ([]string, error) {
	aliases := []string{path}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || !strings.HasSuffix(path, ".app") {
		return aliases, nil
	}
	out, err := s.Runner.Run(ctx, Plutil, "-extract", "CFBundleIdentifier", "raw", "-o", "-", filepath.Join(path, "Contents", "Info.plist"))
	if err != nil {
		return nil, fmt.Errorf("read bundle identifier: %w", err)
	}
	id := strings.TrimSpace(string(out))
	if id == "" || strings.ContainsAny(id, " \t\n/") {
		return nil, fmt.Errorf("unrecognized bundle identifier")
	}
	return append(aliases, id), nil
}

func (s SystemResolver) VerifySigned(ctx context.Context, path string) (AppIdentity, error) {
	if _, err := s.Runner.Run(ctx, Codesign, "--verify", "-R=anchor apple generic", path); err != nil {
		return AppIdentity{}, fmt.Errorf("code signature is not valid and anchored to Apple (Apple, App Store or Developer ID): %w", err)
	}
	out, err := s.Runner.Run(ctx, Codesign, "-d", "-v", path)
	if err != nil {
		return AppIdentity{}, fmt.Errorf("read code signature identity: %w", err)
	}
	var identity AppIdentity
	for _, line := range strings.Split(string(out), "\n") {
		if value, ok := strings.CutPrefix(line, "Identifier="); ok {
			identity.Identifier = strings.TrimSpace(value)
		}
		if value, ok := strings.CutPrefix(line, "TeamIdentifier="); ok {
			identity.TeamID = strings.TrimSpace(value)
		}
	}
	if identity.Identifier == "" {
		return AppIdentity{}, fmt.Errorf("code signature has no identifier")
	}
	return identity, nil
}
