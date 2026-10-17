package security

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

type checksFixtureRunner struct {
	output map[string]string
	errs   map[string]error
	calls  []string
}

func (r *checksFixtureRunner) Run(_ context.Context, path string, args ...string) ([]byte, error) {
	key := path + " " + strings.Join(args, " ")
	r.calls = append(r.calls, key)
	if !allowedCommand(path, args) {
		return nil, errors.New("unexpected command")
	}
	return []byte(r.output[key]), r.errs[key]
}
func checksOutput(path, output string) *checksFixtureRunner {
	return &checksFixtureRunner{output: map[string]string{path: output}, errs: map[string]error{}}
}

const listenerCommand = "/usr/sbin/lsof -nP -iTCP -sTCP:LISTEN -Ts -F pufPnT"

func listenerFixture(bind string) string { return "p123\nu501\nf4\nPTCP\nn" + bind + "\nTST=LISTEN\n" }

// These fixtures prove complete selected lsof records retain only attribution;
// malformed records cannot create a listener result or leak their raw contents.
func TestExposureListenerParser(t *testing.T) {
	valid := listenerFixture("127.0.0.1:80") + "f5\nPTCP\nn[::]:81\nTST=LISTEN\n"
	want := []Listener{{123, 501, "127.0.0.1:80", "TCP"}, {123, 501, "[::]:81", "TCP"}}
	got, ok := parseListeners(valid)
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v %v", got, ok)
	}
	for _, raw := range []string{"p1\nu501\n", "p1\nu501\n" + valid, strings.Replace(valid, "TST=LISTEN", "TST=ESTABLISHED", 1), strings.Replace(valid, "PTCP", "PUDP", 1), strings.Replace(valid, "u501", "uowner-secret", 1), strings.Replace(valid, "n127.0.0.1:80", "nsecret.example:80", 1), strings.Replace(valid, "p123", "p+123", 1), valid + "csecret argv\n", strings.TrimSuffix(valid, "\n"), strings.Replace(valid, "f4", "f4\nPTCP", 1)} {
		if result, ok := parseListeners(raw); ok || result != nil {
			t.Fatalf("accepted malformed listener fixture")
		}
	}
}

// Real macOS lsof 4.91 output (testdata, captured 2026-10-18) carries TQR=/TQS=
// after TST=LISTEN despite -Ts; it parses to one listener per file record.
// Limit: the fixture is a user-view capture; root output has the same fields.
func TestExposureListenerParserRealLsof(t *testing.T) {
	raw, err := os.ReadFile("testdata/lsof-listen-host-261018.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := parseListeners(string(raw))
	want := []Listener{{1037, 501, "*:49173", "TCP"}, {1037, 501, "*:49173", "TCP"}, {1041, 501, "*:7000", "TCP"}, {1041, 501, "*:7000", "TCP"}, {1041, 501, "*:5000", "TCP"}, {1041, 501, "*:5000", "TCP"}, {1123, 501, "127.0.0.1:11434", "TCP"}, {1125, 501, "127.0.0.1:9001", "TCP"}}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v %v", got, ok)
	}
	r := checksOutput(listenerCommand, string(raw))
	if c := listenerExposure(context.Background(), r); c.Status != "partial" {
		t.Fatalf("real output check %#v", c)
	}
}

// The queue fields are accepted only in their exact numeric form, once per
// file and inside a file record; ST=LISTEN stays mandatory, and an unknown T
// field or line kind still refuses the whole output (control: the first case).
func TestExposureListenerParserQueueFields(t *testing.T) {
	base := "p7\nu0\nf3\nPTCP\nn*:22\nTST=LISTEN\n"
	if got, ok := parseListeners(base + "TQR=0\nTQS=12\n"); !ok || len(got) != 1 {
		t.Fatalf("control refused: %#v %v", got, ok)
	}
	for name, raw := range map[string]string{
		"unknown T field":      base + "TQR=0\nTQS=0\nTWIN=65535\n",
		"duplicate QR":         base + "TQR=0\nTQR=0\n",
		"duplicate QS":         base + "TQS=0\nTQS=1\n",
		"non-numeric QR":       base + "TQR=-1\n",
		"empty QS":             base + "TQS=\n",
		"queue without LISTEN": "p7\nu0\nf3\nPTCP\nn*:22\nTQR=0\nTQS=0\n",
		"queue before file":    "p7\nu0\nTQR=0\nf3\nPTCP\nn*:22\nTST=LISTEN\n",
		"unknown line kind":    base + "TQR=0\nTQS=0\nccommand-name\n",
		"duplicate ST":         base + "TST=LISTEN\n",
	} {
		if result, ok := parseListeners(raw); ok || result != nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Loopback controls remain unflagged, while IPv4/IPv6 wildcard, non-loopback,
// and scoped IPv6 binds produce warnings without claiming network reachability.
func TestExposureBindClassificationAndVisibility(t *testing.T) {
	for _, tc := range []struct {
		bind    string
		warning bool
	}{{"127.0.0.1:80", false}, {"[::1]:80", false}, {"*:80", true}, {"0.0.0.0:80", true}, {"[::]:80", true}, {"192.0.2.1:80", true}, {"[fe80::1%en0]:80", true}} {
		t.Run(tc.bind, func(t *testing.T) {
			r := checksOutput(listenerCommand, listenerFixture(tc.bind))
			c := listenerExposure(context.Background(), r)
			if c.Status != "partial" || !c.RequiresRoot {
				t.Fatalf("visibility %#v", c)
			}
			warning := false
			for _, f := range c.Findings {
				if f.Code == "non_loopback_listener" {
					warning = true
				}
			}
			if warning != tc.warning {
				t.Fatalf("warning=%v want %v", warning, tc.warning)
			}
		})
	}
	for _, bind := range []string{"localhost:80", "127.0.0.1:+80", "127.0.0.1:0", "127.0.0.1:65536", "[::1%secret value]:80", "127.0.0.1:80->192.0.2.1:42"} {
		if validListenerBind(bind) {
			t.Fatal("accepted invalid bind")
		}
	}
}

// Empty success and lsof's empty exit-1 case mean no visible TCP listeners,
// still partial; other failures discard output and never echo error secrets.
func TestExposureListenerEmptyAndFailure(t *testing.T) {
	for _, err := range []error{nil, &exec.ExitError{ProcessState: checksExitOne(t)}} {
		r := checksOutput(listenerCommand, "")
		r.errs[listenerCommand] = err
		c := listenerExposure(context.Background(), r)
		if c.Status != "partial" || len(c.Data["listeners"].([]Listener)) != 0 {
			t.Fatalf("empty result %#v", c)
		}
	}
	r := checksOutput(listenerCommand, listenerFixture("*:80"))
	r.errs[listenerCommand] = errors.New("secret-password")
	c := listenerExposure(context.Background(), r)
	b, _ := json.Marshal(c)
	if c.Status != "unavailable" || strings.Contains(string(b), "secret-password") || c.Data != nil {
		t.Fatalf("failure %#v", c)
	}
}
func checksExitOne(t *testing.T) *os.ProcessState {
	t.Helper()
	cmd := exec.Command("/usr/bin/false")
	_ = cmd.Run()
	if cmd.ProcessState == nil {
		t.Fatal("cannot construct exit status")
	}
	return cmd.ProcessState
}

// Known firewall states are accepted; unknown, localized, conflicting, empty,
// and failed responses cannot be interpreted as protection enabled.
func TestExposureFirewallStrictStates(t *testing.T) {
	for _, tc := range []struct{ out, state string }{{"Firewall is disabled. (State = 0)", "disabled"}, {"Firewall is enabled. (State = 1)\n", "enabled"}, {"Firewall is enabled. (State = 2)", "block_all"}} {
		c := firewallExposure(context.Background(), checksOutput("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate", tc.out))
		if c.Status != "ok" || c.Data["state"] != tc.state {
			t.Fatalf("state %#v", c)
		}
	}
	for _, out := range []string{"", "enabled", "Firewall is enabled. (State = 0)", "Firewall is enabled. (State = 1)\nsecret", "Firewall ist aktiviert."} {
		c := firewallExposure(context.Background(), checksOutput("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate", out))
		if c.Status != "unavailable" {
			t.Fatal("accepted unknown firewall response")
		}
	}
	for _, tc := range []struct{ out, state string }{{"Firewall stealth mode is on", "enabled"}, {"Firewall stealth mode is off", "disabled"}} {
		c := stealthExposure(context.Background(), checksOutput("/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode", tc.out))
		if c.Status != "ok" || c.Data["state"] != tc.state {
			t.Fatalf("stealth %#v", c)
		}
	}
	c := stealthExposure(context.Background(), checksOutput("/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode", "stealth enabled"))
	if c.Status != "unavailable" {
		t.Fatal("accepted unknown stealth response")
	}
}

// A canonical pf state and counter block parses; permission failures, duplicate
// statuses, and unrelated text never yield a known packet-filter state.
func TestExposurePacketFilterStrictState(t *testing.T) {
	key := "/sbin/pfctl -s info"
	good := "Status: Enabled for 0 days 00:01:02           Debug: Urgent\n\nState Table                          Total             Rate\n  current entries                        0\n  searches                               0            0.0/s\nCounters\n  match                                  0            0.0/s\n"
	for _, state := range []string{"Enabled", "Disabled"} {
		c := packetFilterExposure(context.Background(), checksOutput(key, strings.Replace(good, "Enabled", state, 1)))
		if c.Status != "ok" || c.Data["state"] != strings.ToLower(state) {
			t.Fatalf("pf %#v", c)
		}
	}
	for _, bad := range []string{"", good + "secret\n", good + good, "Status: Enabled", "localized\n" + good, strings.Replace(good, "00:01:02", "99:99:99", 1), strings.Replace(good, "Debug: Urgent", "Debug: Unknown", 1)} {
		c := packetFilterExposure(context.Background(), checksOutput(key, bad))
		if c.Status != "unavailable" {
			t.Fatal("accepted malformed pf response")
		}
	}
	r := checksOutput(key, good)
	r.errs[key] = errors.New("permission secret")
	c := packetFilterExposure(context.Background(), r)
	if c.Status != "unavailable" || !c.RequiresRoot {
		t.Fatalf("pf failure %#v", c)
	}
}

// Missing overrides remain unknown; explicit true/false values describe only
// overrides. Malformed and duplicate entries cannot make sharing look disabled.
func TestExposureSharingCoverage(t *testing.T) {
	key := "/bin/launchctl print-disabled system"
	raw := "disabled services = {\n \"com.openssh.sshd\" => true\n \"com.apple.smbd\" => false\n}"
	c := sharingExposure(context.Background(), checksOutput(key, raw))
	if c.Status != "partial" {
		t.Fatalf("sharing %#v", c)
	}
	states := c.Data["services"].(map[string]string)
	if states["remote_login"] != "disabled_by_override" || states["file_sharing"] != "enabled_by_override" || states["screen_sharing"] != "unknown" || states["remote_management"] != "unknown" {
		t.Fatalf("states %#v", states)
	}
	for _, raw := range []string{"", "{}", "disabled services = {\n \"com.openssh.sshd\" => true\n \"com.openssh.sshd\" => false\n}", "disabled services = {\n \"com.openssh.sshd\" => maybe\n}"} {
		c := sharingExposure(context.Background(), checksOutput(key, raw))
		if c.Status != "unavailable" {
			t.Fatal("accepted malformed sharing response")
		}
	}
}
