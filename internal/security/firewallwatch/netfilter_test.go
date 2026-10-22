package firewallwatch

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const testSender = "/Library/SystemExtensions/60F57771-7BE8-4402-A569-B4F441ED4FC8/works.relux.mac-infra.netfilter.extension.systemextension/Contents/MacOS/works.relux.mac-infra.netfilter.extension"

func nfEvent(over map[string]any) map[string]any {
	e := map[string]any{
		"ts": "2026-10-23T01:00:00Z", "flow_id": "F", "direction": "outbound", "proto": "tcp",
		"remote_hostname": "api.github.com", "remote_host": "140.82.121.6", "remote_port": 443, "local_port": 50123,
		"app_signing_id": "com.apple.curl", "app_team_id": nil, "app_path": "/usr/bin/curl", "app_pid": 42,
		"app_signing_status": "signed", "app_identity_source": "audit_token", "via_process_path": nil,
	}
	for k, v := range over {
		if v == "<delete>" {
			delete(e, k)
		} else {
			e[k] = v
		}
	}
	return e
}

func nfLine(t *testing.T, event map[string]any, record map[string]any) []byte {
	t.Helper()
	msg, _ := json.Marshal(event)
	r := map[string]any{"subsystem": "works.relux.mac-infra.netfilter", "category": "flow", "processImagePath": testSender, "senderImagePath": testSender, "userID": 0, "eventMessage": string(msg)}
	for k, v := range record {
		if v == "<delete>" {
			delete(r, k)
		} else {
			r[k] = v
		}
	}
	b, _ := json.Marshal(r)
	return b
}

// A flow line from the installed extension maps onto the Item fields the
// rules and classifier already use: direction as kind, path as app, the
// signing facts as signer, the service port by direction, and a class and
// bucket for the destination (named public flows are "internet").
func TestNetfilterParseMapsFlow(t *testing.T) {
	var p NetfilterParser
	it := p.Parse(nfLine(t, nfEvent(nil), nil))
	if it == nil {
		t.Fatalf("valid line refused: %+v", p)
	}
	if it.Source != SourceNetfilter || it.Kind != "outbound" || it.App != "/usr/bin/curl" || it.Signer != "Apple" || it.Verdict != "observed" ||
		it.Remote != "internet" || it.Bucket != "github.com" || it.Host != "api.github.com" || it.RemotePort == nil || *it.RemotePort != 443 || it.LocalPort != nil {
		t.Fatalf("outbound mapping: %+v", it)
	}
	in := p.Parse(nfLine(t, nfEvent(map[string]any{"direction": "inbound", "remote_hostname": nil, "remote_host": "192.168.1.14", "local_port": 5353, "remote_port": 5353}), nil))
	if in == nil || in.Kind != "inbound" || in.LocalPort == nil || *in.LocalPort != 5353 || in.RemotePort != nil || in.Remote != "lan" || in.Bucket != "192.168.1.0/24" {
		t.Fatalf("inbound mapping: %+v", in)
	}
	if p.Invalid != 0 || p.RejectedSender != 0 {
		t.Fatalf("counters: %+v", p)
	}
}

// Signing status maps to the existing signer labels; identity falls back
// from path to signing id to "unknown".
func TestNetfilterSignerAndApp(t *testing.T) {
	for _, tc := range []struct {
		over        map[string]any
		signer, app string
	}{
		{map[string]any{"app_team_id": "2DC432GLL2", "app_path": "/opt/homebrew/bin/codex"}, "Team: 2DC432GLL2", "/opt/homebrew/bin/codex"},
		{map[string]any{"app_signing_status": "adhoc", "app_path": "/opt/homebrew/bin/sing-box"}, "ad-hoc", "/opt/homebrew/bin/sing-box"},
		{map[string]any{"app_signing_status": "unsigned"}, "unsigned", "/usr/bin/curl"},
		{map[string]any{"app_signing_status": "unverified", "app_path": nil}, "unknown", "com.apple.curl"},
		{map[string]any{"app_signing_status": "unresolved", "app_identity_source": "none", "app_path": nil, "app_signing_id": nil}, "unknown", "unknown"},
	} {
		var p NetfilterParser
		it := p.Parse(nfLine(t, nfEvent(tc.over), nil))
		if it == nil || it.Signer != tc.signer || it.App != tc.app {
			t.Errorf("%v: %+v", tc.over, it)
		}
	}
}

// Destination classes: a bare public IP is internet-raw-ip with an address
// bucket; loopback stays loopback; a multi-tun fake-ip address with a name is
// internet bucketed by name; a scoped IPv6 address parses.
func TestNetfilterRemoteClass(t *testing.T) {
	for _, tc := range []struct {
		host, name    any
		class, bucket string
	}{
		{"1.1.1.1", nil, "internet-raw-ip", "1.1.1.0/24"},
		{"127.0.0.1", nil, "loopback", "127.0.0.0/24"},
		{"198.18.0.7", "www.bbc.co.uk", "internet", "bbc.co.uk"},
		{"fe80::1%en0", nil, "lan", "fe80::/64"},
		{nil, nil, "internet-raw-ip", "unknown"},
	} {
		var p NetfilterParser
		it := p.Parse(nfLine(t, nfEvent(map[string]any{"remote_host": tc.host, "remote_hostname": tc.name}), nil))
		if it == nil || it.Remote != tc.class || it.Bucket != tc.bucket {
			t.Errorf("%v/%v: %+v", tc.host, tc.name, it)
		}
	}
	for host, want := range map[string]string{"a.b.github.com": "github.com", "bbc.co.uk": "bbc.co.uk", "x.bbc.co.uk": "bbc.co.uk", "localhost": "localhost", "e6858.dsce9.akamaiedge.net": "akamaiedge.net"} {
		if got := registrableName(host); got != want {
			t.Errorf("registrableName(%s) = %s, want %s", host, got, want)
		}
	}
}

// Negative: only flow lines whose logd-recorded sender is the installed
// extension, running as root, are accepted. A forged subsystem from another
// process, a look-alike path, a library sender inside another process, or a
// non-root sender is counted as rejected_sender and never becomes an item.
// Lines of other subsystems are ignored without counting.
func TestNetfilterRejectsForeignSenders(t *testing.T) {
	for _, rec := range []map[string]any{
		{"processImagePath": "/Users/alexis/bin/forger", "senderImagePath": "/Users/alexis/bin/forger"},
		{"processImagePath": "/tmp/works.relux.mac-infra.netfilter.extension", "senderImagePath": "/tmp/works.relux.mac-infra.netfilter.extension"},
		{"processImagePath": "/private/tmp" + testSender, "senderImagePath": "/private/tmp" + testSender},
		{"processImagePath": testSender + ".copy", "senderImagePath": testSender + ".copy"},
		{"processImagePath": strings.Replace(testSender, "60F57771", "60f57771", 1), "senderImagePath": strings.Replace(testSender, "60F57771", "60f57771", 1)},
		{"processImagePath": "/Library/SystemExtensions/../../tmp/x/works.relux.mac-infra.netfilter.extension.systemextension/Contents/MacOS/works.relux.mac-infra.netfilter.extension"},
		{"senderImagePath": "/usr/lib/libSystem.B.dylib"},
		{"userID": 501},
		{"userID": "<delete>"},
	} {
		var p NetfilterParser
		if it := p.Parse(nfLine(t, nfEvent(nil), rec)); it != nil || p.RejectedSender != 1 || p.Invalid != 0 {
			t.Errorf("%v: item=%v counters=%+v", rec, it, p)
		}
	}
	var p NetfilterParser
	if it := p.Parse(nfLine(t, nfEvent(nil), map[string]any{"subsystem": "com.example.other"})); it != nil || p.RejectedSender != 0 || p.Invalid != 0 {
		t.Fatalf("other subsystem: %v %+v", it, p)
	}
}

// Negative: malformed or out-of-contract events are counted invalid and
// dropped: unknown keys, bad enums, out-of-range ports, invalid or overlong
// hostnames, unbounded text, trailing data, non-JSON and oversized lines.
func TestNetfilterRejectsInvalidEvents(t *testing.T) {
	cases := []map[string]any{
		{"extra": 1},
		{"direction": "sideways"},
		{"app_signing_status": "trusted"},
		{"app_identity_source": "guess"},
		{"remote_port": 0},
		{"local_port": 70000},
		{"remote_hostname": "bad host"},
		{"remote_hostname": strings.Repeat("a.", 127) + "com"},
		{"app_path": strings.Repeat("x", 1025)},
		{"app_team_id": "bad\nteam"},
	}
	for _, over := range cases {
		var p NetfilterParser
		if it := p.Parse(nfLine(t, nfEvent(over), nil)); it != nil || p.Invalid != 1 {
			t.Errorf("%v: item=%v counters=%+v", over, it, p)
		}
	}
	msg, _ := json.Marshal(nfEvent(nil))
	for _, line := range [][]byte{
		nfLine(t, nfEvent(nil), map[string]any{"eventMessage": string(msg) + `{"x":1}`}),
		[]byte("not json"),
		[]byte(`{"eventMessage":"` + strings.Repeat("x", LineLimit) + `"}`),
	} {
		var p NetfilterParser
		if it := p.Parse(line); it != nil || p.Invalid != 1 {
			t.Errorf("line %.40q: item=%v counters=%+v", line, it, p)
		}
	}
	// Positive control: the same builder with no override is accepted.
	var p NetfilterParser
	if p.Parse(nfLine(t, nfEvent(nil), nil)) == nil {
		t.Fatal("control refused")
	}
}

// A netfilter destination is part of the item identity: two registrable
// destinations of one app are two entries, subdomains of one destination are
// one. The nettop key is unchanged (buckets within a class collapse).
// Events keep direction and hostname, and a stored bad hostname is refused.
func TestNetfilterKeyAndEvents(t *testing.T) {
	s, e := OpenStore(testConfig(t))
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	classify := func(Item) Decision { return Decision{Label: "digest", Reason: "test"} }
	var p NetfilterParser
	for _, name := range []string{"api.github.com", "codeload.github.com", "www.apple.com"} {
		it := p.Parse(nfLine(t, nfEvent(map[string]any{"remote_hostname": name}), nil))
		s.Observe(*it, now, classify)
	}
	if len(s.State.Entries) != 2 {
		t.Fatalf("netfilter entries: %d", len(s.State.Entries))
	}
	ev := s.State.Events[len(s.State.Events)-1]
	if ev.Source != SourceNetfilter || ev.Kind != "outbound" || ev.Host != "www.apple.com" || ev.Bucket != "apple.com" {
		t.Fatalf("event: %+v", ev)
	}
	n1 := Item{Source: "nettop", Kind: "outbound", App: "x", Verdict: "observed", Remote: "internet-raw-ip", Bucket: "1.1.1.0/24", RemotePort: intp(443), Count: 1}
	n2 := n1
	n2.Bucket = "8.8.8.0/24"
	if key(n1) != key(n2) {
		t.Fatal("nettop key now depends on the bucket")
	}
	if e = s.Save(now); e != nil {
		t.Fatal(e)
	}
	s.State.Events[0].Host = "bad host"
	if e = s.Save(now); e == nil {
		t.Fatal("invalid stored hostname saved")
	}
}

// policy_unsigned_outbound fires for netfilter ad-hoc or unsigned outbound
// flows to the internet only: not for LAN destinations, not for signed
// apps, and not for nettop items (their behaviour is unchanged).
func TestNetfilterUnsignedOutboundRule(t *testing.T) {
	base := Item{Source: SourceNetfilter, Kind: "outbound", App: "/opt/homebrew/bin/sing-box", Signer: "ad-hoc", Verdict: "observed", Remote: "internet", RemotePort: intp(443), Count: 1}
	if d, ok := Rules(base); !ok || d.Reason != "policy_unsigned_outbound" {
		t.Fatalf("adhoc internet: %+v %v", d, ok)
	}
	unsigned := base
	unsigned.Signer = "unsigned"
	if d, _ := Rules(unsigned); d.Reason != "policy_unsigned_outbound" {
		t.Fatalf("unsigned: %+v", d)
	}
	for name, it := range map[string]Item{
		"lan":    func() Item { i := base; i.Remote = "lan"; return i }(),
		"signed": func() Item { i := base; i.Signer = "Team: ABC"; return i }(),
		"nettop": func() Item { i := base; i.Source = "nettop"; return i }(),
	} {
		if d, _ := Rules(it); d.Reason == "policy_unsigned_outbound" {
			t.Errorf("%s fired: %+v", name, d)
		}
	}
}

// Coverage is tracked per source: netfilter stalls and ends never move the
// ALF span and vice versa; the digest window's gaps use ALF spans only, so
// netfilter coverage cannot hide an ALF gap; a span with an unknown source is
// refused on save.
func TestCoveragePerSource(t *testing.T) {
	s, e := OpenStore(testConfig(t))
	if e != nil {
		t.Fatal(e)
	}
	t0 := time.Now().Truncate(time.Second).Add(-time.Hour)
	at := func(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }
	s.BeginCoverage(at(0))
	s.BeginSourceCoverage(SourceNetfilter, at(0))
	s.Coverage(SourceNetfilter).StallCoverage(at(1))
	s.EndCoverage(at(2))
	if e = s.Save(at(3)); e != nil {
		t.Fatal(e)
	}
	s.Coverage(SourceNetfilter).ResumeCoverage(at(4))
	if e = s.Save(at(6)); e != nil {
		t.Fatal(e)
	}
	var alf, nf []CoverageSpan
	for _, span := range s.State.Coverage {
		if span.Source == "" {
			alf = append(alf, span)
		} else {
			nf = append(nf, span)
		}
	}
	if len(alf) != 1 || !alf[0].End.Equal(at(2)) {
		t.Fatalf("alf spans: %+v", alf)
	}
	if len(nf) != 2 || !nf[0].End.Equal(at(1)) || !nf[1].Start.Equal(at(4)) || !nf[1].End.Equal(at(6)) {
		t.Fatalf("netfilter spans: %+v", nf)
	}
	w := s.Split(at(0), at(6)).Window
	if !w.Truncated || len(w.CoverageGaps) != 1 || !w.CoverageGaps[0].From.Equal(at(2)) || !w.CoverageGaps[0].To.Equal(at(6)) {
		t.Fatalf("ALF window gap hidden or moved by netfilter spans: %+v", w)
	}
	s.State.Coverage = append(s.State.Coverage, CoverageSpan{Start: at(7), End: at(7), Source: "mystery"})
	if e = s.Save(at(8)); e == nil {
		t.Fatal("unknown span source saved")
	}
}
