package firewallwatch

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
)

// SourceNetfilter names items, events and coverage spans that come from the
// netfilter content-filter system extension (apps/netfilter).
const SourceNetfilter = "netfilter"

// NetfilterPredicate selects the extension's per-flow log lines.
const NetfilterPredicate = `subsystem == "works.relux.mac-infra.netfilter" AND category == "flow"`

// netfilterSender is the only process image allowed to produce flow lines:
// the installed system extension. Any local process can log under any
// subsystem name, but logd records the sender image itself, and
// /Library/SystemExtensions is root-owned and SIP-protected.
var netfilterSender = regexp.MustCompile(`^/Library/SystemExtensions/[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/works\.relux\.mac-infra\.netfilter\.extension\.systemextension/Contents/MacOS/works\.relux\.mac-infra\.netfilter\.extension$`)

var hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,62})(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,62}))*\.?$`)

// NetfilterParser turns `log stream --style ndjson` records into Items. It
// counts what it refuses instead of storing it.
type NetfilterParser struct {
	Invalid        uint64 `json:"invalid"`
	RejectedSender uint64 `json:"rejected_sender"`
}

type netfilterRecord struct {
	Subsystem        string `json:"subsystem"`
	Category         string `json:"category"`
	ProcessImagePath string `json:"processImagePath"`
	SenderImagePath  string `json:"senderImagePath"`
	UserID           *int   `json:"userID"`
	EventMessage     string `json:"eventMessage"`
}

// netfilterEvent is the extension's flow event; unknown keys are refused.
type netfilterEvent struct {
	TS             string  `json:"ts"`
	FlowID         string  `json:"flow_id"`
	Direction      string  `json:"direction"`
	Proto          any     `json:"proto"`
	RemoteHostname *string `json:"remote_hostname"`
	RemoteHost     *string `json:"remote_host"`
	RemotePort     *int    `json:"remote_port"`
	LocalPort      *int    `json:"local_port"`
	AppSigningID   *string `json:"app_signing_id"`
	AppTeamID      *string `json:"app_team_id"`
	AppPath        *string `json:"app_path"`
	AppPID         *int    `json:"app_pid"`
	SigningStatus  string  `json:"app_signing_status"`
	IdentitySource string  `json:"app_identity_source"`
	ViaProcessPath *string `json:"via_process_path"`
}

func boundedText(p *string, limit int) bool { return p == nil || persistedText(*p, limit) }
func validPort(p *int) bool                 { return p == nil || (*p >= 1 && *p <= 65535) }

// Parse returns the Item for one ndjson record, or nil when the record is not
// a flow line of the installed extension or fails validation.
func (p *NetfilterParser) Parse(line []byte) *Item {
	var r netfilterRecord
	if len(line) > LineLimit || json.Unmarshal(line, &r) != nil {
		p.Invalid++
		return nil
	}
	if r.Subsystem != "works.relux.mac-infra.netfilter" || r.Category != "flow" {
		return nil
	}
	if !netfilterSender.MatchString(r.ProcessImagePath) || r.SenderImagePath != r.ProcessImagePath || r.UserID == nil || *r.UserID != 0 {
		p.RejectedSender++
		return nil
	}
	var e netfilterEvent
	d := json.NewDecoder(bytes.NewReader([]byte(r.EventMessage)))
	d.DisallowUnknownFields()
	if d.Decode(&e) != nil || d.More() {
		p.Invalid++
		return nil
	}
	it, ok := netfilterItem(e)
	if !ok {
		p.Invalid++
		return nil
	}
	return &it
}

func netfilterItem(e netfilterEvent) (Item, bool) {
	if e.Direction != "outbound" && e.Direction != "inbound" {
		return Item{}, false
	}
	switch e.SigningStatus {
	case "signed", "adhoc", "unsigned", "unverified", "unresolved":
	default:
		return Item{}, false
	}
	switch e.IdentitySource {
	case "audit_token", "pid_path", "none":
	default:
		return Item{}, false
	}
	if !validPort(e.RemotePort) || !validPort(e.LocalPort) || !boundedText(e.AppPath, 1024) || !boundedText(e.AppSigningID, 256) ||
		!boundedText(e.AppTeamID, 32) || !boundedText(e.RemoteHost, 256) || !boundedText(e.ViaProcessPath, 1024) {
		return Item{}, false
	}
	host := ""
	if e.RemoteHostname != nil {
		host = strings.ToLower(strings.TrimSuffix(*e.RemoteHostname, "."))
		if len(host) > 253 || !hostnamePattern.MatchString(host) {
			return Item{}, false
		}
	}
	it := Item{Source: SourceNetfilter, Kind: e.Direction, Verdict: "observed", Count: 1, Host: host, App: "unknown"}
	switch {
	case e.AppPath != nil && *e.AppPath != "":
		it.App = *e.AppPath
	case e.AppSigningID != nil && *e.AppSigningID != "":
		it.App = *e.AppSigningID
	}
	it.Signer = netfilterSigner(e)
	// The remote port identifies an outbound service; for inbound flows the
	// local (listening) port does, and the peer's port is ephemeral.
	if e.Direction == "outbound" {
		it.RemotePort = e.RemotePort
	} else {
		it.LocalPort = e.LocalPort
	}
	it.Remote, it.Bucket = netfilterRemote(e.RemoteHost, host)
	return it, true
}

// netfilterSigner maps the extension's signing facts onto the signer labels
// the rules already use ("Apple", "ad-hoc", "unsigned", "unknown").
func netfilterSigner(e netfilterEvent) string {
	switch e.SigningStatus {
	case "unsigned":
		return "unsigned"
	case "adhoc":
		return "ad-hoc"
	case "signed":
		if e.AppTeamID != nil && *e.AppTeamID != "" {
			return "Team: " + *e.AppTeamID
		}
		// Certificate-signed code without a team identifier is Apple platform code.
		return "Apple"
	}
	return "unknown"
}

// netfilterRemote classifies the destination. A flow opened by name to a
// public address is "internet"; one opened to a bare public IP is
// "internet-raw-ip". The bucket is the destination's registrable name, or
// the address prefix when there is no name.
func netfilterRemote(remoteHost *string, hostname string) (class, bucket string) {
	class, bucket = "internet-raw-ip", ""
	if remoteHost != nil {
		if a, e := netip.ParseAddr(strings.Trim(*remoteHost, "[]")); e == nil {
			class, bucket, _ = BucketIP(a.WithZone("").String())
		} else if hostname == "" && hostnamePattern.MatchString(*remoteHost) {
			hostname = strings.ToLower(strings.TrimSuffix(*remoteHost, "."))
		}
	}
	if hostname != "" {
		if class == "internet-raw-ip" {
			class = "internet"
		}
		bucket = registrableName(hostname)
	}
	if bucket == "" {
		bucket = "unknown"
	}
	// Events bound buckets to 128 bytes; keep the more specific right-hand end.
	if len(bucket) > 128 {
		bucket = bucket[len(bucket)-128:]
	}
	return class, bucket
}

// registrableName approximates the registrable domain (eTLD+1) without a
// public-suffix list: the last two labels, or three when the second-level
// label is a common generic one under a two-letter country code (co.uk).
func registrableName(host string) string {
	labels := strings.Split(host, ".")
	n := 2
	if len(labels) >= 3 && len(labels[len(labels)-1]) == 2 {
		switch labels[len(labels)-2] {
		case "co", "com", "net", "org", "gov", "edu", "ac":
			n = 3
		}
	}
	if len(labels) <= n {
		return host
	}
	return strings.Join(labels[len(labels)-n:], ".")
}
