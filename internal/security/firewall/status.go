package firewall

import (
	"context"
	"fmt"

	"github.com/relux-works/mac-infra/internal/security"
)

var lsofListenerArgs = []string{"-nP", "-iTCP", "-sTCP:LISTEN", "-Ts", "-F", "pufPnT"}

// Listener is socket attribution only; process names and argv are never
// collected, matching the security module.
type Listener struct {
	security.Listener
	NonLoopback bool `json:"non_loopback"`
}

// Status reads the firewall state and the TCP listeners. Run as root inside
// the helper it sees every process; UDP is not inspected.
func (e Engine) Status(ctx context.Context) Report {
	state, err := Observe(ctx, e.Runner)
	if err != nil {
		return Report{Outcome: OutcomeRefused, Error: err.Error()}
	}
	report := Report{Outcome: OutcomeStatus, Before: &state, Listeners: []Listener{}}
	out, err := e.Runner.Run(ctx, Lsof, lsofListenerArgs...)
	// lsof exits 1 with no output when nothing listens.
	if err != nil && !(exitCode(err) == 1 && len(out) == 0) {
		report.Error = fmt.Sprintf("listener inspection: %v", err)
		return report
	}
	listeners, ok := security.ParseListeners(string(out))
	if !ok {
		report.Error = "listener output was not recognized"
		return report
	}
	for _, l := range listeners {
		report.Listeners = append(report.Listeners, Listener{Listener: l, NonLoopback: security.NonLoopbackBind(l.Bind)})
	}
	return report
}

// SeedConfig turns the current state into a starting config for review:
// every setting explicit, path entries listed, mode "listed" so applying it
// unchanged is a no-op. Bundle-id entries cannot be listed by path.
func SeedConfig(state State) (Config, []string) {
	cfg := Config{
		Schema:                SchemaV1,
		Stealth:               boolPtr(state.Stealth),
		BlockAll:              boolPtr(state.BlockAll),
		AllowSignedBuiltin:    boolPtr(state.AllowSignedBuiltin),
		AllowSignedDownloaded: boolPtr(state.AllowSignedDownloaded),
		Apps:                  AppsConfig{Mode: ModeListed, Allow: []string{}, Block: []string{}},
		Services:              ServicesConfig{Disable: []string{}},
	}
	var unaddressable []string
	for _, app := range state.Apps {
		switch {
		case validateAppPath(app.Name) != nil:
			unaddressable = append(unaddressable, app.Name)
		case app.Allowed:
			cfg.Apps.Allow = append(cfg.Apps.Allow, app.Name)
		default:
			cfg.Apps.Block = append(cfg.Apps.Block, app.Name)
		}
	}
	return cfg, unaddressable
}

func boolPtr(value bool) *bool { return &value }
