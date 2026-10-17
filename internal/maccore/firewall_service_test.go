package maccore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/mac-infra/internal/security/firewall"
)

// staticFirewallRunner answers reads with a fixed disabled-firewall host and
// records every command; it never changes state.
type staticFirewallRunner struct {
	calls []string
}

func (r *staticFirewallRunner) Run(_ context.Context, path string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, strings.Join(append([]string{path}, args...), " "))
	switch strings.Join(append([]string{path}, args...), " ") {
	case firewall.SocketFilterFW + " --getglobalstate":
		return []byte("Firewall is disabled. (State = 0)\n"), nil
	case firewall.SocketFilterFW + " --getblockall":
		return []byte("Firewall has block all state set to disabled.\n"), nil
	case firewall.SocketFilterFW + " --getstealthmode":
		return []byte("Firewall stealth mode is off\n"), nil
	case firewall.SocketFilterFW + " --getallowsigned":
		return []byte("Automatically allow built-in signed software ENABLED.\nAutomatically allow downloaded signed software ENABLED.\n"), nil
	case firewall.SocketFilterFW + " --listapps":
		return []byte("Total number of apps = 0 \n"), nil
	case firewall.Launchctl + " print-disabled system":
		return []byte("disabled services = {\n\t\"org.apache.httpd\" => enabled\n}\n"), nil
	case firewall.Launchctl + " print system/org.apache.httpd":
		return []byte("system/org.apache.httpd = {\n}\n"), nil
	}
	return []byte("ok\n"), nil
}

func (r *staticFirewallRunner) mutations() []string {
	var result []string
	for _, call := range r.calls {
		if !strings.Contains(call, " --get") && !strings.HasSuffix(call, "--listapps") && !strings.Contains(call, " print") {
			result = append(result, call)
		}
	}
	return result
}

type memoryFirewallStore struct {
	entries   []string
	managed   bool
	appendErr error
}

func (s *memoryFirewallStore) Append(entry []byte) error {
	if s.appendErr != nil {
		return s.appendErr
	}
	s.entries = append(s.entries, string(entry))
	return nil
}
func (s *memoryFirewallStore) Managed() (bool, error)     { return s.managed, nil }
func (s *memoryFirewallStore) MarkManaged(_ []byte) error { s.managed = true; return nil }

func testFirewallService(runner firewall.Runner, store firewallStore) *firewallService {
	service := newFirewallServiceWith(firewall.Engine{Runner: runner}, store)
	service.now = func() time.Time { return time.Unix(0, 0) }
	return service
}

func ownerFirewallConfig() *firewall.Config {
	return &firewall.Config{Schema: firewall.SchemaV1, Apps: firewall.AppsConfig{Mode: firewall.ModeListed}, Services: firewall.ServicesConfig{Disable: []string{"apache"}}}
}

// Claim: the daemon re-validates configs itself and refuses malformed
// requests before running any command; a valid plan reads the host only.
func TestFirewallServiceRevalidatesRequests(t *testing.T) {
	runner := &staticFirewallRunner{}
	service := testFirewallService(runner, &memoryFirewallStore{})
	bad := ownerFirewallConfig()
	bad.Schema = "mac-infra.firewall/v0"
	for name, response := range map[string]Response{
		"apply without config": service.handle(ActionFirewallApply, nil, 501, 1),
		"status with config":   service.handle(ActionFirewallStatus, ownerFirewallConfig(), 501, 1),
		"invalid schema":       service.handle(ActionFirewallApply, bad, 501, 1),
		"unknown action":       service.handle("firewall_off", ownerFirewallConfig(), 501, 1),
	} {
		if response.OK || response.Error == "" {
			t.Errorf("%s: response accepted: %+v", name, response)
		}
	}
	if len(runner.calls) != 0 {
		t.Fatalf("refused requests ran commands: %v", runner.calls)
	}
	plan := service.handle(ActionFirewallPlan, ownerFirewallConfig(), 501, 1)
	if !plan.OK || plan.Firewall == nil || len(plan.Firewall.Plan.Steps) != 3 || len(runner.mutations()) != 0 {
		t.Fatalf("control plan: %+v, mutations %v", plan, runner.mutations())
	}
}

// Claim: apply fails closed when the audit cannot be written: nothing is
// changed. Positive control: with a working audit the same apply mutates
// and records intent and result.
func TestFirewallApplyFailsClosedWithoutAudit(t *testing.T) {
	runner := &staticFirewallRunner{}
	response := testFirewallService(runner, &memoryFirewallStore{appendErr: errors.New("disk full")}).handle(ActionFirewallApply, ownerFirewallConfig(), 501, 1)
	if response.OK || len(runner.mutations()) != 0 {
		t.Fatalf("apply without audit: ok=%v mutations=%v", response.OK, runner.mutations())
	}
	control := &staticFirewallRunner{}
	store := &memoryFirewallStore{}
	testFirewallService(control, store).handle(ActionFirewallApply, ownerFirewallConfig(), 501, 1)
	if len(control.mutations()) == 0 || len(store.entries) != 2 || !strings.Contains(store.entries[0], `"apply_intent"`) {
		t.Fatalf("control: mutations %v, audit %v", control.mutations(), store.entries)
	}
}

// Claim: keep-on enforcement does nothing until an apply marked the
// firewall as managed; afterwards it turns the firewall on and audits it.
func TestFirewallEnforcementOnlyWhenManaged(t *testing.T) {
	runner := &staticFirewallRunner{}
	store := &memoryFirewallStore{}
	service := testFirewallService(runner, store)
	service.enforce()
	if len(runner.calls) != 0 {
		t.Fatalf("unmanaged enforcement ran commands: %v", runner.calls)
	}
	store.managed = true
	service.enforce()
	if got := strings.Join(runner.mutations(), ";"); got != firewall.SocketFilterFW+" --setglobalstate on" {
		t.Fatalf("managed enforcement mutations = %q", got)
	}
	if len(store.entries) != 1 || !strings.Contains(store.entries[0], `"enforce"`) {
		t.Fatalf("enforcement audit = %v", store.entries)
	}
}

func testStore(t *testing.T) (trustedFirewallStore, string) {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	return trustedFirewallStore{openParent: func() (*os.File, error) { return os.Open(parent) }, owner: uint32(os.Getuid())}, parent
}

// Claim: the trusted store appends audit lines and records the managed
// marker under a verified directory with non-writable modes.
func TestTrustedFirewallStoreWrites(t *testing.T) {
	store, parent := testStore(t)
	for _, entry := range []string{`{"a":1}`, `{"b":2}`} {
		if err := store.Append([]byte(entry)); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(filepath.Join(parent, firewallStateDirectory, firewallAuditFile))
	if err != nil || string(data) != "{\"a\":1}\n{\"b\":2}\n" {
		t.Fatalf("audit = %q, %v", data, err)
	}
	if managed, err := store.Managed(); err != nil || managed {
		t.Fatalf("fresh store managed = %v, %v", managed, err)
	}
	if err := store.MarkManaged([]byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if managed, err := store.Managed(); err != nil || !managed {
		t.Fatalf("marked store managed = %v, %v", managed, err)
	}
}

// Claim: the store refuses a symlinked state directory, a group-writable
// audit file and a group-writable parent instead of writing through them.
func TestTrustedFirewallStoreRefusesUntrustedPaths(t *testing.T) {
	t.Run("symlinked directory", func(t *testing.T) {
		store, parent := testStore(t)
		elsewhere := t.TempDir()
		if err := os.Symlink(elsewhere, filepath.Join(parent, firewallStateDirectory)); err != nil {
			t.Fatal(err)
		}
		if err := store.Append([]byte(`{}`)); err == nil {
			t.Fatal("append through a symlinked directory succeeded")
		}
		if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
			t.Fatalf("symlink target was written: %v", entries)
		}
	})
	t.Run("group-writable audit file", func(t *testing.T) {
		store, parent := testStore(t)
		if err := store.Append([]byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(parent, firewallStateDirectory, firewallAuditFile), 0o664); err != nil {
			t.Fatal(err)
		}
		if err := store.Append([]byte(`{}`)); err == nil {
			t.Fatal("append to a group-writable audit file succeeded")
		}
	})
	t.Run("group-writable parent", func(t *testing.T) {
		store, parent := testStore(t)
		if err := os.Chmod(parent, 0o775); err != nil {
			t.Fatal(err)
		}
		if err := store.Append([]byte(`{}`)); err == nil {
			t.Fatal("append below a group-writable parent succeeded")
		}
	})
}

// Claim: a firewall request that cannot get the turn in time is refused as
// busy without running a command; once the turn is free the same request
// is served (control).
func TestFirewallBusyRefusesInsteadOfQueueing(t *testing.T) {
	runner := &staticFirewallRunner{}
	service := testFirewallService(runner, &memoryFirewallStore{})
	service.queueTimeout = 20 * time.Millisecond
	service.turn <- struct{}{}
	if response := service.handle(ActionFirewallPlan, ownerFirewallConfig(), 501, 1); response.OK || !strings.Contains(response.Error, "busy") || len(runner.calls) != 0 {
		t.Fatalf("busy response = %+v, calls %v", response, runner.calls)
	}
	service.release()
	if response := service.handle(ActionFirewallPlan, ownerFirewallConfig(), 501, 1); !response.OK {
		t.Fatalf("control plan = %+v", response)
	}
}

// Claim: enforcement still sends the enable command when the audit store
// fails (intentional asymmetry with apply, which fails closed), and the
// failure is logged instead of discarded. The static runner does not change
// state, so this proves the attempt, not a successful readback (TestEnforceOn
// covers readback).
func TestEnforcementLogsAuditFailure(t *testing.T) {
	var log strings.Builder
	original := enforcementLog
	enforcementLog = &log
	t.Cleanup(func() { enforcementLog = original })
	runner := &staticFirewallRunner{}
	testFirewallService(runner, &memoryFirewallStore{managed: true, appendErr: errors.New("disk full")}).enforce()
	if got := strings.Join(runner.mutations(), ";"); got != firewall.SocketFilterFW+" --setglobalstate on" {
		t.Fatalf("mutations = %q", got)
	}
	if !strings.Contains(log.String(), "audit failed: disk full") {
		t.Fatalf("log = %q", log.String())
	}
}

// Claim: a hard-linked managed marker is refused before it is truncated, so
// the other link keeps its bytes.
func TestMarkManagedRefusalPreservesHardLink(t *testing.T) {
	store, parent := testStore(t)
	if err := store.Append([]byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(parent, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep me\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(sentinel, filepath.Join(parent, firewallStateDirectory, firewallManagedFile)); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkManaged([]byte(`{}`)); err == nil {
		t.Fatal("marker write through a hard link succeeded")
	}
	if data, _ := os.ReadFile(sentinel); string(data) != "keep me\n" {
		t.Fatalf("sentinel = %q", data)
	}
}
