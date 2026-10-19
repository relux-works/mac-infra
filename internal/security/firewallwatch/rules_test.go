package firewallwatch

import (
	"testing"
)

// Each rule has an activating example and a one-feature nearby control that
// cannot activate that rule; another safety rule may still classify the control.
func TestRuleBranches(t *testing.T) {
	base := Item{App: "/Applications/Test.app", Kind: "outbound", Signer: "Developer ID: Test", Verdict: "allow", Remote: "internet", RemotePort: intp(443), Count: 4}
	for _, tc := range []struct {
		id, label          string
		positive, negative func(*Item)
	}{
		{"hard_deny_spike", "decide", func(i *Item) { i.Spike = true }, func(i *Item) { i.Spike = false }},
		{"hard_non_allow", "decide", func(i *Item) { i.Verdict = "verdict_code:9" }, func(i *Item) { i.Verdict = "allow" }},
		{"hard_unsigned_inbound", "decide", func(i *Item) { i.Kind = "inbound"; i.Signer = "ad-hoc" }, func(i *Item) { i.Kind = "outbound" }},
		{"policy_user_path", "decide", func(i *Item) { i.App = "/private/tmp/svc" }, func(i *Item) { i.App = "/Applications/svc" }},
		{"policy_raw_ip", "decide", func(i *Item) { i.Remote = "internet-raw-ip" }, func(i *Item) { i.Remote = "internet" }},
		{"policy_upload_spike", "decide", func(i *Item) { i.MBOut = 1000; i.Count = 3 }, func(i *Item) { i.MBOut = 999 }},
		{"policy_exposed_service", "decide", func(i *Item) { i.Kind = "inbound"; i.App = "/usr/bin/python3"; i.Remote = "lan" }, func(i *Item) { i.Remote = "loopback" }},
		{"policy_torrent", "decide", func(i *Item) { i.Kind = "inbound"; i.App = "/Applications/Transmission.app" }, func(i *Item) { i.Remote = "lan" }},
		{"policy_non_network_app", "decide", func(i *Item) { i.App = "/System/Applications/Calculator.app"; i.Signer = "Apple" }, func(i *Item) { i.Kind = "inbound" }},
		{"policy_unusual_port", "decide", func(i *Item) { i.RemotePort = intp(4444) }, func(i *Item) { i.RemotePort = intp(443) }},
		{"policy_apple_lan", "noise", func(i *Item) {
			i.Kind = "inbound"
			i.App = "/usr/libexec/rapportd"
			i.Signer = "Apple"
			i.Remote = "lan"
		}, func(i *Item) { i.Remote = "internet" }},
		{"policy_apple_outbound", "noise", func(i *Item) { i.App = "/usr/libexec/apsd"; i.Signer = "Apple" }, func(i *Item) { i.RemotePort = intp(8443) }},
	} {
		t.Run(tc.id, func(t *testing.T) {
			it := base
			tc.positive(&it)
			d, ok := Rules(it)
			if !ok || d.Reason != tc.id || d.Label != tc.label {
				t.Fatalf("positive %+v", d)
			}
			tc.negative(&it)
			d, _ = Rules(it)
			if d.Reason == tc.id {
				t.Fatalf("negative %+v", d)
			}
		})
	}
}

// Regression: an ALF "KNOWN APP FLOW" allow for unsigned, ad-hoc or no-DR code is
// inbound acceptance and hits the hard rule even with the parser's Kind "unknown";
// the same signer on a nettop outbound observation, or an Apple-signed ALF allow,
// does not hit it.
func TestHardUnsignedCoversALFUnknownKind(t *testing.T) {
	for _, signer := range []string{"unsigned", "ad-hoc", "no designated requirement (bundle id only)"} {
		it := Item{Source: "alf", Kind: "unknown", Remote: "unknown", App: "/Applications/Tool.app", Signer: signer, Verdict: "allow", Count: 1}
		if d, ok := Rules(it); !ok || d.Reason != "hard_unsigned_inbound" || d.Label != "decide" {
			t.Fatalf("alf %q: %+v", signer, d)
		}
		out := Item{Source: "nettop", Kind: "outbound", Remote: "internet", RemotePort: intp(443), App: "/Applications/Tool.app", Signer: signer, Verdict: "observed", Count: 1}
		if d, _ := Rules(out); d.Reason == "hard_unsigned_inbound" {
			t.Fatalf("nettop %q: %+v", signer, d)
		}
	}
	signed := Item{Source: "alf", Kind: "unknown", Remote: "unknown", App: "/Applications/Tool.app", Signer: "Apple", Verdict: "allow", Count: 1}
	if d, _ := Rules(signed); d.Reason == "hard_unsigned_inbound" {
		t.Fatalf("signed alf: %+v", d)
	}
}

// Prompt-looking names remain data; all supplied injection examples are decided
// by features, without asking the embedder. Versioned interpreters also escalate.
func TestInjectionAndInterpreter(t *testing.T) {
	for _, file := range []string{"testdata/fixtures-v1.jsonl", "testdata/fixtures-v2-heldout.jsonl"} {
		items, e := LoadItems(file)
		if e != nil {
			t.Fatal(e)
		}
		for _, it := range items {
			if it.ID == "fx083" || it.ID == "fx084" || it.ID == "fx085" || it.ID == "ho031" {
				d, ok := Rules(it)
				if !ok || d.Label != "decide" {
					t.Fatalf("%s %+v", it.ID, d)
				}
			}
		}
	}
	for _, name := range []string{"python3.13", "ruby3.4", "node22"} {
		it := Item{Kind: "inbound", App: "/usr/bin/" + name, Signer: "Apple", Verdict: "allow", Remote: "lan"}
		d, ok := Rules(it)
		if !ok || d.Reason != "policy_exposed_service" {
			t.Fatal(name, d)
		}
	}
	// Similar names alone do not establish an interpreter executable.
	if d, ok := Rules(Item{Kind: "inbound", App: "/Applications/pythonista", Signer: "Apple", Verdict: "allow", Remote: "lan"}); ok {
		t.Fatal(d)
	}
}
