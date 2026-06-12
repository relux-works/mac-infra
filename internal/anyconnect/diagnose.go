package anyconnect

import (
	"fmt"
	"io"
	"strings"

	"github.com/relux-works/mac-infra/internal/loadprofile"
)

const (
	SocketFilterBundleID = "com.cisco.anyconnect.macos.acsockext"
	VPNAgentLabel        = "com.cisco.anyconnect.vpnagentd"
)

type VPNState string

const (
	VPNStateConnected    VPNState = "connected"
	VPNStateDisconnected VPNState = "disconnected"
	VPNStateUnknown      VPNState = "unknown"
)

type Diagnostic struct {
	VPNState              VPNState
	VPNStatusError        string
	SystemExtensionFound  bool
	SystemExtensionState  string
	SystemExtensionTeamID string
	SocketFilterProcesses []loadprofile.Process
	VPNAgentProcesses     []loadprofile.Process
	LogHints              []string
}

func Analyze(processes []loadprofile.Process, vpnStatusOutput, vpnStatusError, systemExtensionsOutput, logOutput string) Diagnostic {
	socketFilters, agents := AnyConnectProcesses(processes)
	found, teamID, state := ParseSystemExtension(systemExtensionsOutput)
	return Diagnostic{
		VPNState:              ParseVPNState(vpnStatusOutput),
		VPNStatusError:        strings.TrimSpace(vpnStatusError),
		SystemExtensionFound:  found,
		SystemExtensionState:  state,
		SystemExtensionTeamID: teamID,
		SocketFilterProcesses: socketFilters,
		VPNAgentProcesses:     agents,
		LogHints:              LogHints(logOutput, 12),
	}
}

func AnyConnectProcesses(processes []loadprofile.Process) ([]loadprofile.Process, []loadprofile.Process) {
	var socketFilters []loadprofile.Process
	var agents []loadprofile.Process
	for _, process := range processes {
		command := strings.ToLower(process.Command)
		switch {
		case strings.Contains(command, SocketFilterBundleID):
			socketFilters = append(socketFilters, process)
		case strings.Contains(command, "vpnagentd"):
			agents = append(agents, process)
		}
	}
	return loadprofile.SortByPID(socketFilters), loadprofile.SortByPID(agents)
}

func ParseVPNState(output string) VPNState {
	lower := strings.ToLower(output)
	for _, line := range strings.Split(lower, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(line, ">>"))
		if !strings.Contains(line, "state:") {
			continue
		}
		switch {
		case strings.Contains(line, "disconnected"):
			return VPNStateDisconnected
		case strings.Contains(line, "connected"):
			return VPNStateConnected
		}
	}
	if strings.Contains(lower, "disconnected") {
		return VPNStateDisconnected
	}
	if strings.Contains(lower, "connected") && !strings.Contains(lower, "disconnected") {
		return VPNStateConnected
	}
	return VPNStateUnknown
}

func ParseSystemExtension(output string) (bool, string, string) {
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.Contains(line, SocketFilterBundleID) {
			continue
		}
		fields := strings.Fields(line)
		teamID := ""
		for _, field := range fields {
			if len(field) == 10 && strings.ToUpper(field) == field {
				teamID = field
				break
			}
		}
		state := ""
		if start := strings.LastIndex(line, "["); start >= 0 {
			if end := strings.LastIndex(line, "]"); end > start {
				state = line[start+1 : end]
			}
		}
		return true, teamID, state
	}
	return false, "", ""
}

func LogHints(output string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	var hints []string
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		hints = append(hints, line)
		if len(hints) == limit {
			break
		}
	}
	return hints
}

func Suspicious(d Diagnostic, cpuThreshold float64, rssThresholdBytes int64) bool {
	if d.VPNState != VPNStateDisconnected {
		return false
	}
	for _, process := range d.SocketFilterProcesses {
		if process.CPU >= cpuThreshold || process.RSSKB*1024 >= rssThresholdBytes {
			return true
		}
	}
	return false
}

func PrintDiagnostic(w io.Writer, d Diagnostic) {
	fmt.Fprintf(w, "vpn_state: %s\n", d.VPNState)
	if d.VPNStatusError != "" {
		fmt.Fprintf(w, "vpn_status_error: %s\n", d.VPNStatusError)
	}
	if d.SystemExtensionFound {
		fmt.Fprintf(w, "socket_filter_extension: %s", SocketFilterBundleID)
		if d.SystemExtensionTeamID != "" {
			fmt.Fprintf(w, " team=%s", d.SystemExtensionTeamID)
		}
		if d.SystemExtensionState != "" {
			fmt.Fprintf(w, " state=%s", d.SystemExtensionState)
		}
		fmt.Fprintln(w)
	} else {
		fmt.Fprintln(w, "socket_filter_extension: not-found")
	}

	fmt.Fprintf(w, "socket_filter_processes: %d\n", len(d.SocketFilterProcesses))
	printProcessGroup(w, d.SocketFilterProcesses)
	fmt.Fprintf(w, "vpnagentd_processes: %d\n", len(d.VPNAgentProcesses))
	printProcessGroup(w, d.VPNAgentProcesses)

	if Suspicious(d, 25, 512*1024*1024) {
		fmt.Fprintln(w, "warning: AnyConnect is disconnected, but the socket filter is still hot or large")
		fmt.Fprintln(w, "cleanup_hint: mac-infra-core anyconnect-cleanup")
	}

	if len(d.LogHints) == 0 {
		fmt.Fprintln(w, "log_hints: none")
		return
	}
	fmt.Fprintf(w, "log_hints: %d\n", len(d.LogHints))
	for _, hint := range d.LogHints {
		fmt.Fprintf(w, "- %s\n", hint)
	}
}

func printProcessGroup(w io.Writer, processes []loadprofile.Process) {
	if len(processes) == 0 {
		fmt.Fprintln(w, "none")
		return
	}
	loadprofile.PrintTable(w, processes)
}
