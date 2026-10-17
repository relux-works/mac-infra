package security

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Listener contains socket attribution only; process names and argv are never collected.
type Listener struct {
	PID      int    `json:"pid"`
	OwnerUID uint64 `json:"owner_uid"`
	Bind     string `json:"bind"`
	Protocol string `json:"protocol"`
}

func securityResult(name, status string) Check {
	return Check{Name: name, Status: status, Findings: []Finding{}}
}
func securityUnavailable(name, detail string, root bool) Check {
	c := securityResult(name, "unavailable")
	c.RequiresRoot = root
	c.Findings = append(c.Findings, Finding{Check: name, Severity: "info", Code: "unavailable", Detail: detail})
	return c
}

// Exposure performs read-only local inspection; it never probes the network.
func Exposure(ctx context.Context, r Runner) []Check {
	return []Check{Observe(ctx, r, listenerExposure), Observe(ctx, r, firewallExposure), Observe(ctx, r, stealthExposure), Observe(ctx, r, packetFilterExposure), Observe(ctx, r, sharingExposure)}
}
func listenerExposure(ctx context.Context, r Runner) Check {
	const name = "listeners"
	b, err := r.Run(ctx, "/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Ts", "-F", "pufPnT")
	if err != nil {
		var exit *exec.ExitError
		if !(len(b) == 0 && errors.As(err, &exit) && exit.ExitCode() == 1) {
			return securityUnavailable(name, "Listener inspection did not complete.", true)
		}
	}
	listeners, ok := parseListeners(string(b))
	if !ok {
		return securityUnavailable(name, "Listener output was not recognized.", true)
	}
	c := securityResult(name, "partial")
	c.RequiresRoot = true
	c.Data = map[string]any{"listeners": listeners, "coverage": "visible TCP listeners only; complete process visibility is not established; UDP is not inspected"}
	c.Findings = append(c.Findings, Finding{Check: name, Severity: "info", Code: "visibility_limited", Detail: "Visible TCP listeners do not establish the absence of other listeners; complete visibility may require root."})
	for _, l := range listeners {
		if NonLoopbackBind(l.Bind) {
			c.Findings = append(c.Findings, Finding{Check: name, Severity: "warning", Code: "non_loopback_listener", Detail: "A visible TCP listener accepts a wildcard or non-loopback bind; reachability depends on routing and firewall policy."})
		}
	}
	return c
}

// NonLoopbackBind reports a wildcard or non-loopback listener address.
func NonLoopbackBind(bind string) bool {
	host, _, _ := net.SplitHostPort(bind)
	if i := strings.LastIndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	return host == "*" || (ip != nil && !ip.IsLoopback())
}

// ParseListeners exposes the strict lsof field parser to the firewall status.
func ParseListeners(raw string) ([]Listener, bool) { return parseListeners(raw) }

var listenerDigitsPattern = regexp.MustCompile(`^[0-9]+$`)
var listenerFDPattern = regexp.MustCompile(`^[0-9]+[rwu]?$`)
var listenerScopePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

func parseListeners(raw string) ([]Listener, bool) {
	result := []Listener{}
	if raw == "" {
		return result, true
	}
	if !strings.HasSuffix(raw, "\n") {
		return nil, false
	}
	pid := 0
	var uid uint64
	hasUID := false
	processHasFile := false
	current := Listener{}
	inFile := false
	hasProtocol, hasBind, hasState := false, false, false
	hasRecvQueue, hasSendQueue := false, false
	flush := func() bool {
		if !inFile {
			return true
		}
		if !hasUID || !hasProtocol || !hasBind || !hasState {
			return false
		}
		current.PID = pid
		current.OwnerUID = uid
		result = append(result, current)
		processHasFile = true
		inFile = false
		return true
	}
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		if len(line) < 2 {
			return nil, false
		}
		v := line[1:]
		switch line[0] {
		case 'p':
			if !flush() || (pid != 0 && !processHasFile) {
				return nil, false
			}
			n, e := strconv.Atoi(v)
			if e != nil || n <= 0 || !listenerDigitsPattern.MatchString(v) {
				return nil, false
			}
			pid = n
			hasUID = false
			processHasFile = false
		case 'u':
			if pid == 0 || hasUID || inFile {
				return nil, false
			}
			n, e := strconv.ParseUint(v, 10, 32)
			if e != nil || !listenerDigitsPattern.MatchString(v) {
				return nil, false
			}
			uid = n
			hasUID = true
		case 'f':
			if pid == 0 || !hasUID || !flush() {
				return nil, false
			}
			if !listenerFDPattern.MatchString(v) {
				return nil, false
			}
			inFile = true
			current = Listener{}
			hasProtocol = false
			hasBind = false
			hasState = false
			hasRecvQueue, hasSendQueue = false, false
		case 'P':
			if !inFile || hasProtocol || v != "TCP" {
				return nil, false
			}
			current.Protocol = v
			hasProtocol = true
		case 'n':
			if !inFile || hasBind || !validListenerBind(v) {
				return nil, false
			}
			current.Bind = v
			hasBind = true
		case 'T':
			// lsof 4.91 on macOS adds the queue sizes (QR=, QS=) even with
			// -Ts; they are checked and dropped.
			switch {
			case !inFile:
				return nil, false
			case v == "ST=LISTEN" && !hasState:
				hasState = true
			case strings.HasPrefix(v, "QR=") && !hasRecvQueue && listenerDigitsPattern.MatchString(v[3:]):
				hasRecvQueue = true
			case strings.HasPrefix(v, "QS=") && !hasSendQueue && listenerDigitsPattern.MatchString(v[3:]):
				hasSendQueue = true
			default:
				return nil, false
			}
		default:
			return nil, false
		}
	}
	if !flush() || pid == 0 || !hasUID || len(result) == 0 {
		return nil, false
	}
	return result, true
}
func validListenerBind(bind string) bool {
	host, port, err := net.SplitHostPort(bind)
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || !listenerDigitsPattern.MatchString(port) {
		return false
	}
	if host == "*" {
		return true
	}
	// lsof may retain a numeric IPv6 scope identifier or interface name.
	if i := strings.LastIndexByte(host, '%'); i >= 0 {
		if !listenerScopePattern.MatchString(host[i+1:]) {
			return false
		}
		host = host[:i]
	}
	return net.ParseIP(host) != nil
}
func firewallExposure(ctx context.Context, r Runner) Check {
	const name = "application_firewall"
	b, e := r.Run(ctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
	if e != nil {
		return securityUnavailable(name, "Application firewall state could not be read.", false)
	}
	state := ""
	switch strings.TrimSpace(string(b)) {
	case "Firewall is disabled. (State = 0)":
		state = "disabled"
	case "Firewall is enabled. (State = 1)":
		state = "enabled"
	case "Firewall is enabled. (State = 2)":
		state = "block_all"
	default:
		return securityUnavailable(name, "Application firewall output was not recognized.", false)
	}
	c := securityResult(name, "ok")
	c.Data = map[string]any{"state": state}
	if state == "disabled" {
		c.Findings = append(c.Findings, Finding{Check: name, Severity: "warning", Code: "firewall_disabled", Detail: "The application firewall reports disabled."})
	}
	return c
}
func stealthExposure(ctx context.Context, r Runner) Check {
	const name = "stealth_mode"
	b, e := r.Run(ctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode")
	if e != nil {
		return securityUnavailable(name, "Firewall stealth mode could not be read.", false)
	}
	state := ""
	switch strings.TrimSpace(string(b)) {
	case "Firewall stealth mode is on":
		state = "enabled"
	case "Firewall stealth mode is off":
		state = "disabled"
	default:
		return securityUnavailable(name, "Firewall stealth mode output was not recognized.", false)
	}
	c := securityResult(name, "ok")
	c.Data = map[string]any{"state": state}
	if state == "disabled" {
		c.Findings = append(c.Findings, Finding{Check: name, Severity: "info", Code: "stealth_disabled", Detail: "Firewall stealth mode reports disabled."})
	}
	return c
}

var pfStatusPattern = regexp.MustCompile(`(?m)^Status: (Enabled|Disabled) for [0-9]+ days (?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9][ \t]+Debug: (?:None|Urgent|Misc|Loud)[ \t]*$`)

func packetFilterExposure(ctx context.Context, r Runner) Check {
	const name = "packet_filter"
	b, e := r.Run(ctx, "/sbin/pfctl", "-s", "info")
	if e != nil {
		return securityUnavailable(name, "Packet filter state could not be read; root access may be required.", true)
	}
	m := pfStatusPattern.FindAllStringSubmatch(string(b), -1)
	if len(m) != 1 || !validPFOutput(string(b)) {
		return securityUnavailable(name, "Packet filter output was not recognized.", true)
	}
	c := securityResult(name, "ok")
	c.Data = map[string]any{"state": strings.ToLower(m[0][1]), "coverage": "packet filter enablement only; rules are not inspected"}
	if m[0][1] == "Disabled" {
		c.Findings = append(c.Findings, Finding{Check: name, Severity: "info", Code: "pf_disabled", Detail: "The packet filter reports disabled; application firewall state is reported separately."})
	}
	return c
}

var sharingLabels = map[string]string{"remote_login": "com.openssh.sshd", "screen_sharing": "com.apple.screensharing", "file_sharing": "com.apple.smbd", "remote_management": "com.apple.RemoteDesktop.agent"}
var disabledOverridePattern = regexp.MustCompile(`^"([A-Za-z0-9_.-]+)"[ \t]+=>[ \t]+(true|false)$`)

func sharingExposure(ctx context.Context, r Runner) Check {
	const name = "sharing"
	b, e := r.Run(ctx, "/bin/launchctl", "print-disabled", "system")
	if e != nil {
		return securityUnavailable(name, "Sharing service override coverage could not be read.", false)
	}
	overrides, ok := parseDisabledOverrides(string(b))
	if !ok {
		return securityUnavailable(name, "Sharing service override output was not recognized.", false)
	}
	c := securityResult(name, "partial")
	states := map[string]string{}
	for _, service := range []string{"remote_login", "screen_sharing", "file_sharing", "remote_management"} {
		label := sharingLabels[service]
		states[service] = "unknown"
		if disabled, present := overrides[label]; present {
			if disabled {
				states[service] = "disabled_by_override"
			} else {
				states[service] = "enabled_by_override"
				c.Findings = append(c.Findings, Finding{Check: name, Severity: "warning", Code: "sharing_enabled_override", Detail: "A sharing service has an enabled launchd override: " + service + "; active state and network reachability are not established."})
			}
		}
	}
	c.Data = map[string]any{"services": states, "coverage": "launchd disabled overrides only; active service state, other sharing services, and network reachability are not established"}
	c.Findings = append(c.Findings, Finding{Check: name, Severity: "info", Code: "sharing_coverage_limited", Detail: "Missing launchd overrides are unknown; an override does not establish whether a service is currently active."})
	return c
}
func parseDisabledOverrides(raw string) (map[string]bool, bool) {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[0]) != "disabled services = {" || strings.TrimSpace(lines[len(lines)-1]) != "}" {
		return nil, false
	}
	states := map[string]bool{}
	for _, line := range lines[1 : len(lines)-1] {
		m := disabledOverridePattern.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			return nil, false
		}
		if _, present := states[m[1]]; present {
			return nil, false
		}
		states[m[1]] = m[2] == "true"
	}
	return states, true
}

// Reject extra text rather than treating one recognizable status line inside
// an otherwise unknown response as evidence of packet-filter protection.
var pfTableHeader = regexp.MustCompile(`^(State Table|Source Tracking Table)[ \t]+Total[ \t]+Rate$`)
var pfCounterLine = regexp.MustCompile(`^(current entries|searches|inserts|removals|match|bad-offset|fragment|short|normalize|memory|bad-timestamp|congestion|ip-option|proto-cksum|state-mismatch|state-insert|state-limit|src-limit|synproxy|translate|no-route)[ \t]+[0-9]+(?:[ \t]+[0-9]+\.[0-9]+/s)?$`)

func validPFOutput(raw string) bool {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) == 0 || !pfStatusPattern.MatchString(lines[0]) {
		return false
	}
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line != "" && line != "Counters" && !pfTableHeader.MatchString(line) && !pfCounterLine.MatchString(line) {
			return false
		}
	}
	return true
}
