// mac-firewall manages the macOS application firewall from a declarative
// config through the mac-infra-core root helper. It never asks for sudo:
// the helper is installed once and then serves the configured client user.
// Plan is the default; only `apply --apply` changes the host.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/relux-works/mac-infra/internal/maccore"
	"github.com/relux-works/mac-infra/internal/security/firewall"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

var (
	firewallStatus = maccore.FirewallStatus
	firewallPlan   = maccore.FirewallPlan
	firewallApply  = maccore.FirewallApply
	userHomeDir    = os.UserHomeDir
)

const usage = `mac-firewall status [--json]
mac-firewall plan [--config PATH] [--json]
mac-firewall apply [--config PATH] [--apply] [--json]
mac-firewall init-config [--config PATH]
mac-firewall version

Config: ~/.config/mac-infra/firewall.json (schema mac-infra.firewall/v1) unless --config is given.
apply without --apply only plans. The firewall can be turned on, never off.
Exit 0 success, 1 refused/failed/rolled back, 2 usage.`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, usage)
		return 2
	}
	command := args[0]
	switch command {
	case "help", "--help", "-h":
		fmt.Fprintln(out, usage)
		return 0
	case "version":
		fmt.Fprintf(out, "mac-firewall %s %s %s\n", Version, Commit, BuildDate)
		return 0
	case "status", "plan", "apply", "init-config":
	default:
		fmt.Fprintf(errOut, "unknown command %q\n%s\n", command, usage)
		return 2
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(errOut)
	asJSON := flags.Bool("json", false, "print the helper report as JSON")
	configPath := flags.String("config", "", "firewall config path")
	doApply := flags.Bool("apply", false, "apply the plan (apply only)")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return 2
	}
	if *doApply && command != "apply" || *configPath != "" && command == "status" || *asJSON && command == "init-config" {
		fmt.Fprintln(errOut, "flag not valid for "+command)
		return 2
	}
	path := *configPath
	if path == "" && command != "status" {
		home, err := userHomeDir()
		if err != nil {
			fmt.Fprintln(errOut, "home directory unavailable")
			return 1
		}
		path = filepath.Join(home, ".config", "mac-infra", "firewall.json")
	}
	service := maccore.DefaultServiceConfig()

	switch command {
	case "status":
		response, err := firewallStatus(service)
		return report(out, errOut, *asJSON, response, err, printStatus)
	case "init-config":
		return initConfig(out, errOut, service, path)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	if command == "plan" || !*doApply {
		response, err := firewallPlan(service, cfg)
		code := report(out, errOut, *asJSON, response, err, printPlan)
		if code == 0 && !*asJSON {
			fmt.Fprintln(out, "dry run: nothing changed; run `mac-firewall apply --apply` to apply")
		}
		return code
	}
	response, err := firewallApply(service, cfg)
	return report(out, errOut, *asJSON, response, err, printApply)
}

// loadConfig refuses a config another user could have written: the helper
// would apply whatever it says.
func loadConfig(path string) (firewall.Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return firewall.Config{}, fmt.Errorf("open firewall config: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return firewall.Config{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || int(stat.Uid) != os.Getuid() || info.Mode().Perm()&0o022 != 0 {
		return firewall.Config{}, fmt.Errorf("firewall config %s must be a regular file owned by you and not group- or world-writable", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, firewall.MaxConfigBytes+1))
	if err != nil {
		return firewall.Config{}, err
	}
	return firewall.ParseConfig(data)
}

func initConfig(out, errOut io.Writer, service maccore.ServiceConfig, path string) int {
	response, err := firewallStatus(service)
	if err != nil || response.Firewall == nil || response.Firewall.Before == nil {
		fmt.Fprintf(errOut, "read firewall state through mac-infra-core: %v\n", err)
		return 1
	}
	cfg, unaddressable := firewall.SeedConfig(*response.Firewall.Before)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		fmt.Fprintf(errOut, "%s already exists; init-config never overwrites a config\n", path)
		return 1
	}
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	_, writeErr := file.Write(append(data, '\n'))
	if err := errors.Join(writeErr, file.Close()); err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	fmt.Fprintf(out, "wrote %s from the current state (apps.mode listed: applying it unchanged is a no-op)\n", path)
	for _, name := range unaddressable {
		fmt.Fprintf(out, "not listed (reported by bundle id, not path): %s\n", name)
	}
	return 0
}

func report(out, errOut io.Writer, asJSON bool, response maccore.Response, callErr error, human func(io.Writer, firewall.Report)) int {
	if response.Firewall == nil {
		if callErr == nil {
			callErr = errors.New("mac-infra-core returned no firewall report")
		}
		fmt.Fprintf(errOut, "mac-firewall: %v\n", callErr)
		if maccore.IsUnavailable(callErr) {
			fmt.Fprintln(errOut, "mac-infra-core is not reachable; install it with `mac-infra-core install-digest` then `mac-infra-core install --expect-sha256 HEX`")
		}
		return 1
	}
	if asJSON {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(response.Firewall); err != nil {
			return 1
		}
	} else {
		human(out, *response.Firewall)
	}
	if response.Firewall.Outcome == firewall.OutcomeRollbackFailed {
		fmt.Fprintf(errOut, "INCIDENT: rollback failed; the host differs from its pre-apply state: %s\n", response.Firewall.Drift)
	}
	if callErr != nil {
		fmt.Fprintf(errOut, "mac-firewall: %v\n", callErr)
		return 1
	}
	return 0
}

func printState(out io.Writer, s firewall.State) {
	fmt.Fprintf(out, "firewall: %s  block_all: %s  stealth: %s  allow_signed: built-in %s, downloaded %s\n",
		onOff(s.Enabled), onOff(s.BlockAll), onOff(s.Stealth), onOff(s.AllowSignedBuiltin), onOff(s.AllowSignedDownloaded))
	fmt.Fprintf(out, "apps (%d):\n", len(s.Apps))
	for _, app := range s.Apps {
		policy := "allow"
		if !app.Allowed {
			policy = "block"
		}
		fmt.Fprintf(out, "  %s  %s\n", policy, app.Name)
	}
	for _, service := range s.Services {
		loaded, override := "not loaded", "enabled"
		if service.Loaded {
			loaded = "loaded"
		}
		if service.Disabled {
			override = "disabled"
		}
		fmt.Fprintf(out, "service %s (%s): %s, %s\n", service.Name, service.Label, loaded, override)
	}
}

func printStatus(out io.Writer, r firewall.Report) {
	if r.Before != nil {
		printState(out, *r.Before)
	}
	fmt.Fprintln(out, "TCP listeners on non-loopback addresses (UDP not inspected):")
	for _, l := range r.Listeners {
		if l.NonLoopback {
			fmt.Fprintf(out, "  %s pid %d uid %d\n", l.Bind, l.PID, l.OwnerUID)
		}
	}
}

func printPlan(out io.Writer, r firewall.Report) {
	if r.Plan == nil {
		fmt.Fprintf(out, "%s: %s\n", r.Outcome, r.Error)
		return
	}
	if len(r.Plan.Steps) == 0 {
		fmt.Fprintln(out, "no changes: the host matches the config")
	}
	for _, step := range r.Plan.Steps {
		mark := "tightens"
		if step.Loosens {
			mark = "LOOSENS"
		}
		line := strings.TrimSpace(fmt.Sprintf("%s %s %s", step.Kind, step.Target, step.Value))
		if step.Identity != nil {
			line += fmt.Sprintf(" (signed: %s, team %s)", step.Identity.Identifier, step.Identity.TeamID)
		}
		fmt.Fprintf(out, "  [%s] %s\n", mark, line)
	}
	for _, name := range r.Plan.Unmanaged {
		fmt.Fprintf(out, "  unmanaged (bundle id, not addressable by path): %s\n", name)
	}
}

func printApply(out io.Writer, r firewall.Report) {
	printPlan(out, r)
	fmt.Fprintf(out, "outcome: %s\n", r.Outcome)
	if r.Error != "" {
		fmt.Fprintf(out, "error: %s\n", r.Error)
	}
	for _, c := range r.Rollback {
		fmt.Fprintf(out, "  rollback: %s %s\n", strings.Join(c.Argv, " "), c.Error)
	}
}

func onOff(value bool) string {
	if value {
		return "on"
	}
	return "off"
}
