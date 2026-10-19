package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"testing"

	"github.com/relux-works/mac-infra/internal/security/firewallwatch"
)

// Opt-in only: the pinned real embedding model plus v1 pool must reach >=85%
// accuracy with zero decide->noise on synthetic policy-author self-labelled v2.
// It starts only a foreground child, never a service or host collector.
func TestWatchRealModel(t *testing.T) {
	if os.Getenv("MAC_FIREWALL_REAL_MODEL") != "1" {
		t.Skip("set MAC_FIREWALL_REAL_MODEL=1 to run the pinned real model")
	}
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	config, _ := watchConfig(t, port)
	var out, errOut bytes.Buffer
	code := run([]string{"watch", "classify", "--config", config, "--fixtures", "../../internal/security/firewallwatch/testdata/fixtures-v2-heldout.jsonl", "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatal(code, errOut.String())
	}
	var m firewallwatch.Metrics
	if e = json.Unmarshal(out.Bytes(), &m); e != nil {
		t.Fatal(e)
	}
	t.Log(out.String())
	if m.Accuracy < .85 || m.DecideToNoise != 0 || m.Unavailable != 0 {
		t.Fatalf("quality gate: %+v stderr=%s", m, errOut.String())
	}
}
