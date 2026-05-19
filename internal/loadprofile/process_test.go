package loadprofile

import "testing"

const psFixture = `
  10     1 root          0.0   0.1   1024 01:00:00 /sbin/launchd
 100    10 alexis      445.2   3.2 524288 00:10:00 /opt/homebrew/bin/sing-box run -c config.json
 101   100 alexis       10.0   1.0 131072 00:09:00 helper child process
 200    10 alexis        8.5  15.5 2097152 02:00:00 /Applications/PaperKitExtension
 300    10 alexis       40.0   2.0 262144 00:05:00 vless-tun start
`

func TestParsePS(t *testing.T) {
	processes, err := ParsePS([]byte(psFixture))
	if err != nil {
		t.Fatalf("ParsePS error = %v", err)
	}
	if len(processes) != 5 {
		t.Fatalf("len(processes) = %d, want 5", len(processes))
	}
	if processes[1].PID != 100 || processes[1].CPU != 445.2 || processes[1].Command != "/opt/homebrew/bin/sing-box run -c config.json" {
		t.Fatalf("parsed sing-box process = %#v", processes[1])
	}
}

func TestTopByCPUAndRSS(t *testing.T) {
	processes, err := ParsePS([]byte(psFixture))
	if err != nil {
		t.Fatalf("ParsePS error = %v", err)
	}

	topCPU := TopByCPU(processes, 2)
	if topCPU[0].PID != 100 || topCPU[1].PID != 300 {
		t.Fatalf("top cpu pids = %d, %d; want 100, 300", topCPU[0].PID, topCPU[1].PID)
	}

	topRSS := TopByRSS(processes, 1)
	if topRSS[0].PID != 200 {
		t.Fatalf("top rss pid = %d, want 200", topRSS[0].PID)
	}
}

func TestFilterWithDescendants(t *testing.T) {
	processes, err := ParsePS([]byte(psFixture))
	if err != nil {
		t.Fatalf("ParsePS error = %v", err)
	}

	roots := Filter(processes, "sing-box")
	withChildren := WithDescendants(processes, roots)
	if len(withChildren) != 2 {
		t.Fatalf("len(withChildren) = %d, want 2", len(withChildren))
	}
	if withChildren[0].PID != 100 || withChildren[1].PID != 101 {
		t.Fatalf("descendant pids = %d, %d; want 100, 101", withChildren[0].PID, withChildren[1].PID)
	}
}

func TestFilterAnyTunnelQueries(t *testing.T) {
	processes, err := ParsePS([]byte(psFixture))
	if err != nil {
		t.Fatalf("ParsePS error = %v", err)
	}

	matches := FilterAny(processes, TunnelQueries())
	if len(matches) != 2 {
		t.Fatalf("len(matches) = %d, want 2", len(matches))
	}
	if matches[0].PID != 100 || matches[1].PID != 300 {
		t.Fatalf("tunnel pids = %d, %d; want 100, 300", matches[0].PID, matches[1].PID)
	}
}
