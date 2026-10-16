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
