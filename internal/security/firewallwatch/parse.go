package firewallwatch

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const SampleLimit = 16
const LineLimit = 64 * 1024

var handle = regexp.MustCompile(`^Handle flow with processPID: ([0-9]+) and bundleid: (.+)$`)
var known = regexp.MustCompile(`^KNOWN APP FLOW: (.+), return known verdict: (-?[0-9]+)$`)
var digits = regexp.MustCompile(`[0-9]`)
var ipv4Literal = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)
var ipCandidate = regexp.MustCompile(`[0-9A-Fa-f:.]+(?:%[a-zA-Z0-9]+)?`)

// Sanitize also handles IP literals embedded in untrusted app/signer fields.
func Sanitize(s string) string {
	// Invalid bytes become U+FFFD first, so JSON round trips cannot change the value.
	s = strings.ToValidUTF8(s, "\uFFFD")
	s = ipv4Literal.ReplaceAllStringFunc(s, func(v string) string {
		if _, e := netip.ParseAddr(v); e == nil {
			return "[ip]"
		}
		return v
	})
	s = ipCandidate.ReplaceAllStringFunc(s, func(v string) string {
		if _, e := netip.ParseAddr(v); e == nil {
			return "[ip]"
		}
		// A dot may start a filename suffix or terminate punctuation. Try the
		// full token first (including IPv4-mapped IPv6), then dot boundaries.
		for i := len(v) - 1; i > 0; i-- {
			if v[i] == '.' {
				if a, e := netip.ParseAddr(v[:i]); e == nil && a.Is6() {
					return "[ip]" + v[i:]
				}
			}
		}
		return v
	})
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, s)
	return truncateUTF8(s, 1024)
}

// truncateUTF8 cuts s to at most n bytes without splitting a rune.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

type ALFParser struct {
	Unrecognized uint64   `json:"unrecognized"`
	Invalid      uint64   `json:"invalid_json"`
	Samples      []string `json:"samples"`
}

func (p *ALFParser) unknown(s string) {
	p.Unrecognized++
	s = digits.ReplaceAllString(Sanitize(s), "#")
	s = truncateUTF8(s, 256)
	for _, v := range p.Samples {
		if v == s {
			return
		}
	}
	if len(p.Samples) < SampleLimit {
		p.Samples = append(p.Samples, s)
	}
}
func (p *ALFParser) Parse(line []byte) *Item {
	var v struct {
		Message  string `json:"eventMessage"`
		Category string `json:"category"`
	}
	if len(line) > LineLimit || json.Unmarshal(line, &v) != nil {
		p.Invalid++
		return nil
	}
	if v.Category != "fw" {
		return nil
	}
	it := Item{Source: "alf", Kind: "unknown", Remote: "unknown", Verdict: "unknown", Count: 1, Signer: "unknown"}
	if m := handle.FindStringSubmatch(v.Message); m != nil {
		it.InspectionPath = m[2]
		it.App = Sanitize(m[2])
		return &it
	}
	if m := known.FindStringSubmatch(v.Message); m != nil {
		path := m[1]
		if strings.HasPrefix(path, "file://") {
			u, e := url.Parse(path)
			if e != nil || (u.Host != "" && u.Host != "localhost") {
				p.unknown(v.Message)
				return nil
			}
			path = u.Path
		}
		it.InspectionPath = path
		it.App = Sanitize(path)
		if m[2] == "1" {
			it.Verdict = "allow"
		} else {
			it.Verdict = "verdict_code:" + m[2]
		}
		return &it
	}
	p.unknown(v.Message)
	return nil
}

func BucketIP(s string) (class, bucket string, ok bool) {
	a, e := netip.ParseAddr(s)
	if e != nil {
		return "", "", false
	}
	a = a.Unmap().WithZone("")
	class = "internet-raw-ip"
	switch {
	case a.IsLoopback():
		class = "loopback"
	case netip.MustParsePrefix("100.64.0.0/10").Contains(a) || netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(a):
		class = "tailnet"
	case a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast():
		class = "lan"
	}
	bits := 64
	if a.Is4() {
		bits = 24
	}
	return class, netip.PrefixFrom(a, bits).Masked().String(), true
}
func endpoint(s string) (string, int, bool) {
	s = strings.TrimSpace(s)
	host, p, e := net.SplitHostPort(s)
	if e != nil {
		i := strings.LastIndex(s, ".")
		if i < 0 {
			return "", 0, false
		}
		host, p = s[:i], s[i+1:]
	}
	n, e := strconv.Atoi(p)
	host = strings.Trim(host, "[]")
	if e != nil || n < 1 || n > 65535 {
		return "", 0, false
	}
	return host, n, true
}

// ParseNettop accepts numeric CSV connection rows, never process totals or DNS
// names. Positive bytes_out establishes outbound traffic, not SYN direction.
func ParseNettop(text string) (items []Item, unrecognized uint64) {
	r := csv.NewReader(strings.NewReader(text))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	app, procName, pid := "", "", 0
	byteColumn := -1
	for {
		row, e := r.Read()
		if e != nil {
			if !errors.Is(e, io.EOF) {
				unrecognized++
			}
			break
		}
		if len(row) == 0 {
			continue
		}
		first := strings.TrimSpace(row[0])
		header := false
		for i, c := range row {
			if strings.TrimSpace(c) == "bytes_out" {
				byteColumn = i
				header = true
			}
		}
		if header {
			continue
		}
		if first == "" {
			continue
		}
		if !strings.Contains(first, "<->") && !strings.Contains(first, "->") {
			if i := strings.LastIndex(first, "."); i > 0 {
				if n, e := strconv.Atoi(first[i+1:]); e == nil {
					app, procName, pid = Sanitize(first[:i]), first[:i], n
					continue
				}
			}
			unrecognized++
			app, procName, pid = "", "", 0
			continue
		}
		if app == "" || byteColumn < 0 || byteColumn >= len(row) {
			unrecognized++
			continue
		}
		parts := strings.Split(first, "<->")
		if len(parts) != 2 {
			parts = strings.Split(first, "->")
		}
		if len(parts) != 2 {
			unrecognized++
			continue
		}
		peer, n, ok := endpoint(parts[1])
		if !ok {
			unrecognized++
			continue
		}
		class, bucket, ok := BucketIP(peer)
		if !ok {
			unrecognized++
			continue
		}
		b, e := strconv.ParseUint(strings.TrimSpace(row[byteColumn]), 10, 64)
		if e != nil {
			unrecognized++
			continue
		}
		if b == 0 {
			continue
		}
		items = append(items, Item{Source: "nettop", Kind: "outbound", App: app, Signer: "unknown", Verdict: "observed", Remote: class, RemotePort: &n, Bucket: bucket, MBOut: float64(b) / 1e6, Count: 1, PID: pid, ProcName: procName})
	}
	return
}

// persistedText reports whether a stored string meets the persisted-text
// invariants: valid UTF-8, at most limit bytes, no control characters. The
// validator uses this, not Sanitize idempotence, because a cap cut can turn a
// non-address token into an address-looking fragment.
func persistedText(s string, limit int) bool {
	if len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
