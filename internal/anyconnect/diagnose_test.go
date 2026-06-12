package anyconnect

import (
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/loadprofile"
)

func TestParseVPNState(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		output string
		want   VPNState
	}{
		{
			name: "disconnected",
			output: `
  >> state: Disconnected
  >> notice: Ready to connect.
`,
			want: VPNStateDisconnected,
		},
		{
			name:   "connected",
			output: "  >> state: Connected\n",
			want:   VPNStateConnected,
		},
		{
			name:   "unknown",
			output: "Cisco AnyConnect Secure Mobility Client\n",
			want:   VPNStateUnknown,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ParseVPNState(tc.output); got != tc.want {
				t.Fatalf("ParseVPNState() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseSystemExtension(t *testing.T) {
	t.Parallel()

	found, teamID, state := ParseSystemExtension(`*	*	DE8Y96K9QP	com.cisco.anyconnect.macos.acsockext (4.10.08029/4.10.08029)	Cisco AnyConnect Socket Filter Extension	[activated enabled]`)
	if !found {
		t.Fatal("ParseSystemExtension found = false, want true")
	}
	if teamID != "DE8Y96K9QP" {
		t.Fatalf("teamID = %q, want DE8Y96K9QP", teamID)
	}
	if state != "activated enabled" {
		t.Fatalf("state = %q, want activated enabled", state)
	}
}

func TestAnalyzeFindsSuspiciousDisconnectedSocketFilter(t *testing.T) {
	t.Parallel()

	processes := []loadprofile.Process{
		{
			PID:     614,
			PPID:    1,
			User:    "root",
			CPU:     97.5,
			RSSKB:   890000,
			Elapsed: "10:00",
			Command: "/Library/SystemExtensions/UUID/com.cisco.anyconnect.macos.acsockext.systemextension/Contents/MacOS/com.cisco.anyconnect.macos.acsockext",
		},
		{
			PID:     592,
			PPID:    1,
			User:    "root",
			CPU:     0,
			RSSKB:   30000,
			Elapsed: "10:00",
			Command: "/opt/cisco/anyconnect/bin/vpnagentd -execv_instance",
		},
	}

	diagnostic := Analyze(
		processes,
		">> state: Disconnected",
		"",
		"* * DE8Y96K9QP com.cisco.anyconnect.macos.acsockext Cisco AnyConnect Socket Filter Extension [activated enabled]",
		"acsockext: handleNewUDPFlow\nacsockext: NEFlow opened",
	)

	if diagnostic.VPNState != VPNStateDisconnected {
		t.Fatalf("VPNState = %q, want disconnected", diagnostic.VPNState)
	}
	if len(diagnostic.SocketFilterProcesses) != 1 || len(diagnostic.VPNAgentProcesses) != 1 {
		t.Fatalf("process groups = socket %d agent %d, want 1/1", len(diagnostic.SocketFilterProcesses), len(diagnostic.VPNAgentProcesses))
	}
	if !Suspicious(diagnostic, 25, 512*1024*1024) {
		t.Fatal("Suspicious() = false, want true")
	}

	var out strings.Builder
	PrintDiagnostic(&out, diagnostic)
	for _, want := range []string{
		"vpn_state: disconnected",
		"socket_filter_extension: com.cisco.anyconnect.macos.acsockext",
		"warning: AnyConnect is disconnected",
		"cleanup_hint: mac-infra-core anyconnect-cleanup",
		"log_hints: 2",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("PrintDiagnostic output missing %q:\n%s", want, out.String())
		}
	}
}
