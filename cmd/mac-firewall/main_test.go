package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/maccore"
	"github.com/relux-works/mac-infra/internal/security/firewall"
)

const validConfig = `{"schema":"mac-infra.firewall/v1","apps":{"mode":"listed","allow":[],"block":[]},"services":{"disable":["apache"]}}`

type calls struct{ status, plan, apply int }

func stubHelper(t *testing.T, applyResponse maccore.Response, applyErr error) *calls {
	t.Helper()
	c := &calls{}
	planned := maccore.Response{OK: true, Firewall: &firewall.Report{Outcome: firewall.OutcomePlanned, Plan: &firewall.Plan{Steps: []firewall.Step{{Kind: firewall.StepGlobalOn, Value: "on"}}}}}
	status := maccore.Response{OK: true, Firewall: &firewall.Report{Outcome: firewall.OutcomeStatus, Before: &firewall.State{Apps: []firewall.App{{Name: "/usr/sbin/cupsd", Allowed: true}, {Name: "com.spotify.client", Allowed: true}}}}}
	origStatus, origPlan, origApply := firewallStatus, firewallPlan, firewallApply
	firewallStatus = func(maccore.ServiceConfig) (maccore.Response, error) { c.status++; return status, nil }
	firewallPlan = func(maccore.ServiceConfig, firewall.Config) (maccore.Response, error) { c.plan++; return planned, nil }
	firewallApply = func(maccore.ServiceConfig, firewall.Config) (maccore.Response, error) {
		c.apply++
		return applyResponse, applyErr
	}
	t.Cleanup(func() { firewallStatus, firewallPlan, firewallApply = origStatus, origPlan, origApply })
	return c
}

func writeConfig(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "firewall.json")
	if err := os.WriteFile(path, []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// Claim: apply without --apply is a dry run (plan only); with --apply it
// calls the helper's apply exactly once.
func TestApplyRequiresExplicitFlag(t *testing.T) {
	c := stubHelper(t, maccore.Response{OK: true, Firewall: &firewall.Report{Outcome: firewall.OutcomeApplied, Plan: &firewall.Plan{}}}, nil)
	path := writeConfig(t, 0o600)
	var out, errOut bytes.Buffer
	if code := run([]string{"apply", "--config", path}, &out, &errOut); code != 0 || c.apply != 0 || c.plan != 1 {
		t.Fatalf("dry run: code %d, calls %+v, stderr %s", code, *c, errOut.String())
	}
	if !strings.Contains(out.String(), "dry run: nothing changed") {
		t.Fatalf("dry run output: %s", out.String())
	}
	if code := run([]string{"apply", "--config", path, "--apply"}, &out, &errOut); code != 0 || c.apply != 1 {
		t.Fatalf("apply: code %d, calls %+v, stderr %s", code, *c, errOut.String())
	}
}

// Claim: a config another user could write is refused before the helper is
// contacted; the same file with mode 0600 is accepted (control above).
func TestGroupWritableConfigRefused(t *testing.T) {
	c := stubHelper(t, maccore.Response{}, nil)
	var out, errOut bytes.Buffer
	if code := run([]string{"apply", "--apply", "--config", writeConfig(t, 0o620)}, &out, &errOut); code != 1 || c.plan+c.apply != 0 {
		t.Fatalf("code %d, calls %+v", code, *c)
	}
}

// Claim: a rolled-back or failed rollback apply exits 1, and a failed
// rollback is reported as an incident with the drift.
func TestApplyFailureOutcomes(t *testing.T) {
	stubHelper(t, maccore.Response{Firewall: &firewall.Report{Outcome: firewall.OutcomeRollbackFailed, Drift: "stealth=true", Plan: &firewall.Plan{}}}, errors.New("firewall rollback_failed"))
	var out, errOut bytes.Buffer
	if code := run([]string{"apply", "--apply", "--config", writeConfig(t, 0o600)}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "INCIDENT") {
		t.Fatalf("code %d, stderr %s", code, errOut.String())
	}
}

// Claim: init-config seeds a 0600 config from the helper's state, lists
// bundle-id entries separately, and never overwrites an existing file.
func TestInitConfigSeedsAndNeverOverwrites(t *testing.T) {
	stubHelper(t, maccore.Response{}, nil)
	path := filepath.Join(t.TempDir(), "sub", "firewall.json")
	var out, errOut bytes.Buffer
	if code := run([]string{"init-config", "--config", path}, &out, &errOut); code != 0 {
		t.Fatalf("init: code %d, stderr %s", code, errOut.String())
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("seeded file: %v %v", info, err)
	}
	cfg, err := loadConfig(path)
	if err != nil || strings.Join(cfg.Apps.Allow, ",") != "/usr/sbin/cupsd" || !strings.Contains(out.String(), "com.spotify.client") {
		t.Fatalf("seeded config %+v, err %v, out %s", cfg, err, out.String())
	}
	before, _ := os.ReadFile(path)
	if code := run([]string{"init-config", "--config", path}, &out, &errOut); code != 1 {
		t.Fatalf("second init: code %d", code)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("second init changed the file")
	}
}

// Claim: flags that do not belong to a command are usage errors.
func TestUsageErrors(t *testing.T) {
	c := stubHelper(t, maccore.Response{}, nil)
	for _, args := range [][]string{{"status", "--apply"}, {"plan", "--apply"}, {"off"}, {"status", "extra"}} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != 2 {
			t.Errorf("%v: code %d", args, code)
		}
	}
	if c.status+c.plan+c.apply != 0 {
		t.Fatalf("usage errors contacted the helper: %+v", *c)
	}
}

func stubStatus(t *testing.T, response maccore.Response, err error) {
	t.Helper()
	orig := firewallStatus
	firewallStatus = func(maccore.ServiceConfig) (maccore.Response, error) { return response, err }
	t.Cleanup(func() { firewallStatus = orig })
}

// Claim: init-config seeds from the state of a status report even when the
// helper flagged its listener listing, including a helper installed before
// listener_error existed (error in "error", OK false). Without a state, or
// for a non-status outcome, it refuses and writes nothing.
func TestInitConfigToleratesListenerFailureOnly(t *testing.T) {
	state := &firewall.State{Apps: []firewall.App{{Name: "/usr/sbin/cupsd", Allowed: true}}}
	cases := []struct {
		name     string
		response maccore.Response
		err      error
		want     int
	}{
		{"new helper", maccore.Response{OK: true, Firewall: &firewall.Report{Outcome: firewall.OutcomeStatus, Before: state, ListenerError: "listener output was not recognized"}}, nil, 0},
		{"old helper", maccore.Response{Error: "listener output was not recognized", Firewall: &firewall.Report{Outcome: firewall.OutcomeStatus, Before: state, Error: "listener output was not recognized"}}, errors.New("listener output was not recognized"), 0},
		{"state unreadable", maccore.Response{Error: "socketfilterfw failed", Firewall: &firewall.Report{Outcome: firewall.OutcomeRefused, Error: "socketfilterfw failed"}}, errors.New("socketfilterfw failed"), 1},
		{"status without state", maccore.Response{OK: true, Firewall: &firewall.Report{Outcome: firewall.OutcomeStatus}}, nil, 1},
		{"not a status", maccore.Response{OK: true, Firewall: &firewall.Report{Outcome: firewall.OutcomePlanned, Before: state}}, nil, 1},
		{"helper unreachable", maccore.Response{}, errors.New("dial: no such file"), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubStatus(t, tc.response, tc.err)
			path := filepath.Join(t.TempDir(), "firewall.json")
			var out, errOut bytes.Buffer
			code := run([]string{"init-config", "--config", path}, &out, &errOut)
			_, statErr := os.Stat(path)
			if code != tc.want || (code == 0) != (statErr == nil) {
				t.Fatalf("code %d (want %d), file err %v, stderr %s", code, tc.want, statErr, errOut.String())
			}
		})
	}
}

// Claim: status exits 1 and says the listeners were not inspected when the
// listener listing failed, while still printing the firewall state; a clean
// report exits 0 with the listener section (control).
func TestStatusListenerErrorExitsNonZero(t *testing.T) {
	state := &firewall.State{Enabled: true}
	stubStatus(t, maccore.Response{OK: true, Firewall: &firewall.Report{Outcome: firewall.OutcomeStatus, Before: state, ListenerError: "listener output was not recognized"}}, nil)
	var out, errOut bytes.Buffer
	if code := run([]string{"status"}, &out, &errOut); code != 1 || !strings.Contains(out.String(), "firewall: on") || !strings.Contains(out.String(), "not inspected") || strings.Contains(out.String(), "non-loopback addresses") || !strings.Contains(errOut.String(), "not recognized") {
		t.Fatalf("code %d, out %s, stderr %s", code, out.String(), errOut.String())
	}
	stubStatus(t, maccore.Response{OK: true, Firewall: &firewall.Report{Outcome: firewall.OutcomeStatus, Before: state, Listeners: []firewall.Listener{}}}, nil)
	out.Reset()
	errOut.Reset()
	if code := run([]string{"status"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "non-loopback addresses") {
		t.Fatalf("control: code %d, out %s, stderr %s", code, out.String(), errOut.String())
	}
}
