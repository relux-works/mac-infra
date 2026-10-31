package firewallwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
)

// Observed ALF shapes retain missing direction/port and only literal verdict 1
// means allow. Unknown and malformed rows remain visible in bounded counters.
func TestALF(t *testing.T) {
	for _, tc := range []struct{ message, app, verdict string }{
		{"Handle flow with processPID: 42 and bundleid: com.apple.rapportd", "com.apple.rapportd", "unknown"},
		{"KNOWN APP FLOW: /Applications/Test.app, return known verdict: 1", "/Applications/Test.app", "allow"},
		{"KNOWN APP FLOW: file:///Applications/Test%20App.app, return known verdict: 1", "/Applications/Test App.app", "allow"},
		{"KNOWN APP FLOW: /a, return known verdict: 2", "/a", "verdict_code:2"},
		{"KNOWN APP FLOW: /a, return known verdict: 0", "/a", "verdict_code:0"},
		{"KNOWN APP FLOW: /a, return known verdict: -1", "/a", "verdict_code:-1"},
	} {
		t.Run(tc.message, func(t *testing.T) {
			p := ALFParser{}
			raw, _ := json.Marshal(map[string]string{"category": "fw", "eventMessage": tc.message})
			it := p.Parse(raw)
			if it == nil || it.App != tc.app || it.Verdict != tc.verdict || it.Kind != "unknown" || it.LocalPort != nil {
				t.Fatalf("%+v", it)
			}
		})
	}
	p := ALFParser{}
	if it := p.Parse([]byte(`{"category":"fw","eventMessage":"new decision 123 from 192.168.7.91"}`)); it != nil || p.Unrecognized != 1 || len(p.Samples) != 1 || strings.Contains(p.Samples[0], "123") {
		t.Fatalf("%+v", p)
	}
	if it := p.Parse([]byte(`{"category":"fw","eventMessage":`)); it != nil || p.Invalid != 1 {
		t.Fatal(p)
	}
	if it := p.Parse([]byte(`{"category":"other","eventMessage":"hello"}`)); it != nil || p.Unrecognized != 1 {
		t.Fatal(p)
	}
}

// A 100k-line unique-shape flood cannot grow the sample set or retained heap
// beyond a small fixed allowance; oversize lines resume at the next good row.
func TestALFFlood(t *testing.T) {
	p := ALFParser{}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < 100000; i++ {
		raw, _ := json.Marshal(map[string]string{"category": "fw", "eventMessage": fmt.Sprintf("shape %s %d", strings.Repeat(string(rune('a'+i%26)), 20), i)})
		p.Parse(raw)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if len(p.Samples) != SampleLimit || p.Unrecognized != 100000 || after.HeapAlloc > before.HeapAlloc+8<<20 {
		t.Fatalf("samples=%d count=%d heap before=%d after=%d", len(p.Samples), p.Unrecognized, before.HeapAlloc, after.HeapAlloc)
	}
	count := 0
	err := scanLines(context.Background(), strings.NewReader(strings.Repeat("x", LineLimit*3)+"\n"+`{"category":"fw","eventMessage":"Handle flow with processPID: 2 and bundleid: app"}`+"\n"), func(line []byte) error { p.Parse(line); count++; return nil })
	if err != nil || count != 2 || p.Invalid != 1 {
		t.Fatalf("%v count=%d %+v", err, count, p)
	}
}

// Numeric nettop rows become buckets; zero-byte, malformed, hostname and invalid
// port rows never become flows. Scanning serialized results detects IP leakage.
func TestNettopPrivacy(t *testing.T) {
	raw, e := os.ReadFile("testdata/nettop.csv")
	if e != nil {
		t.Fatal(e)
	}
	items, unknown := ParseNettop(string(raw))
	if len(items) != 7 || unknown != 3 {
		t.Fatalf("items=%d unknown=%d %+v", len(items), unknown, items)
	}
	out, _ := json.Marshal(items)
	for _, ip := range []string{"192.168.50.11", "93.184.216.34", "100.82.17.29", "fd7a:115c:a1e0:abcd::67", "2606:4700:abcd:1234::789", "192.168.50.93", "127.0.0.2", "::1", "2001:db8:1::4", "fe80::a:4"} {
		if strings.Contains(string(out), ip) {
			t.Errorf("raw peer leaked: %s", ip)
		}
	}
	want := []string{"internet-raw-ip", "tailnet", "tailnet", "loopback", "lan", "internet-raw-ip", "loopback"}
	for i, it := range items {
		if it.Remote != want[i] || it.MBOut <= 0 || it.App == "" || it.RemotePort == nil {
			t.Errorf("%+v", it)
		}
	}
	for _, s := range []string{"named.invalid", "1.2.3.999", ""} {
		if _, _, ok := BucketIP(s); ok {
			t.Errorf("accepted %s", s)
		}
	}
	for _, tc := range []struct{ ip, class, bucket string }{{"10.4.5.6", "lan", "10.4.5.0/24"}, {"fd01:2:3:4:5:6:7:8", "lan", "fd01:2:3:4::/64"}, {"100.127.2.3", "tailnet", "100.127.2.0/24"}, {"::1", "loopback", "::/64"}, {"::ffff:100.82.17.29", "tailnet", "100.82.17.0/24"}} {
		class, b, ok := BucketIP(tc.ip)
		if !ok || class != tc.class || b != tc.bucket {
			t.Errorf("%s %s %s", tc.ip, class, b)
		}
	}
	for _, s := range []string{"app 93.184.216.34 end", "app 93.184.216.34.", "app fd7a:115c:a1e0:abcd::67 end"} {
		v := Sanitize(s)
		if !strings.Contains(v, "[ip]") {
			t.Errorf("not sanitized %s", v)
		}
	}
}

// Historical benign transcript labels remain a compatibility reference only;
// production authority never uses this deliberately forgeable text parser.
func TestLegacyTextSignerReference(t *testing.T) {
	for _, tc := range []struct {
		raw    string
		failed bool
		want   string
	}{
		{"code object is not signed at all", true, "unsigned"}, {"Signature=adhoc", false, "ad-hoc"}, {"no designated requirement", true, "no designated requirement"},
		{"Authority=Developer ID Application: Vendor (TEAM)\nAuthority=Apple Root CA", false, "Developer ID: Vendor (TEAM)"},
		{"Authority=Software Signing\nAuthority=Apple Root CA", false, "Apple"},
		{"Authority=Mac App Store Application Signing\nTeamIdentifier=ABC", false, "App Store: ABC"},
		{"Authority=Software Signing\nAuthority=Apple Root CA", true, "unknown"},
		{"", false, "no designated requirement"},
	} {
		if got := legacyTextSigner(tc.raw, tc.failed); got != tc.want {
			t.Errorf("%q: %q", tc.raw, got)
		}
	}
}

// legacyTextSigner preserves the previous reader solely for benign-format
// compatibility controls, never for signer admission.
func legacyTextSigner(output string, failed bool) string {
	switch {
	case strings.Contains(output, "not signed at all"):
		return "unsigned"
	case strings.Contains(output, "Signature=adhoc"):
		return "ad-hoc"
	case strings.Contains(output, "no designated requirement"):
		return "no designated requirement"
	case failed:
		return "unknown"
	case strings.Contains(output, "Authority=Developer ID Application:"):
		for _, line := range strings.Split(output, "\n") {
			if strings.HasPrefix(line, "Authority=Developer ID Application:") {
				return Sanitize("Developer ID: " + strings.TrimSpace(strings.TrimPrefix(line, "Authority=Developer ID Application:")))
			}
		}
	case strings.Contains(output, "Authority=Apple Mac OS Application Signing") || strings.Contains(output, "Authority=Mac App Store Application Signing"):
		for _, line := range strings.Split(output, "\n") {
			if strings.HasPrefix(line, "TeamIdentifier=") {
				return Sanitize("App Store: " + strings.TrimPrefix(line, "TeamIdentifier="))
			}
		}
		return "App Store"
	case strings.Contains(output, "Authority=Software Signing") && strings.Contains(output, "Authority=Apple Root CA"):
		return "Apple"
	}
	return "no designated requirement"
}
