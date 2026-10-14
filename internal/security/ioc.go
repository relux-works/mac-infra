package security

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Rule targets a fixed evidence class, never a user-supplied file or command.
// Patterns are kept private: reports expose only the rule ID and match count.
type Rule struct {
	ID      string `json:"id"`
	Target  string `json:"target"`
	Pattern string `json:"pattern"`
}

func MergeRules(extra []Rule) ([]Rule, error) {
	rules := append(DefaultRules(), extra...)
	return rules, validateRules(rules)
}
func DefaultRules() []Rule {
	return []Rule{
		{"mini-miner-dir", "tmp-name", ".xm5my*"}, {"mini-navcmd", "tmp-name", ".navcmd"}, {"mini-navg", "tmp-name", ".navg"},
		{"mini-mdx", "launch-name", "com.apple.mdx.stores*"}, {"mini-syncagent", "launch-name", "com.apple.metadata.syncagent*"}, {"mini-interval", "launch-name", "com.apple.mdworker.interval4*"}, {"mini-sync", "launch-name", "com.apple.mdworker.sync4*"}, {"mini-sshd", "launch-name", "com.apple.zzsshd*"},
		{"mini-airport", "shell-content", "airportd -c"}, {"mini-c2-shell", "shell-content", "176.58.92.254"}, {"mini-pool-shell", "shell-content", "c3pool"}, {"mini-c2-network", "network", "176.58.92.254"}, {"mini-pool-network", "network", "c3pool"},
	}
}
func validateRules(rules []Rule) error {
	if len(rules) > 128 {
		return errors.New("too many IOC rules")
	}
	ids := map[string]bool{}
	for _, r := range rules {
		if len(r.ID) == 0 || len(r.ID) > 64 || strings.Trim(r.ID, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != "" || ids[r.ID] || len(r.Pattern) == 0 || len(r.Pattern) > 256 {
			return errors.New("invalid IOC rule")
		}
		ids[r.ID] = true
		switch r.Target {
		case "tmp-name", "launch-name":
			if strings.Contains(r.Pattern, "/") {
				return errors.New("invalid IOC name pattern")
			}
			if _, err := filepath.Match(r.Pattern, ""); err != nil {
				return errors.New("invalid IOC glob")
			}
		case "shell-content", "network":
		default:
			return errors.New("invalid IOC target")
		}
	}
	return nil
}
func LoadRules(path string) ([]Rule, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, errors.New("cannot read IOC rules")
	}
	if strictJSON(data) != nil {
		return nil, errors.New("invalid IOC JSON members")
	}
	var rules []Rule
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	if d.Decode(&rules) != nil {
		return nil, errors.New("invalid IOC rules JSON")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, errors.New("trailing IOC data")
	}
	var raw []json.RawMessage
	if json.Unmarshal(data, &raw) != nil {
		return nil, errors.New("invalid IOC rules")
	}
	for _, item := range raw {
		if requiredMembers(item, "id", "target", "pattern") != nil {
			return nil, errors.New("invalid IOC rule members")
		}
	}
	return rules, validateRules(rules)
}
func IOC(ctx context.Context, r Runner, rules []Rule) Check {
	return scanIOC(ctx, r, rules, []string{"/private/var/tmp"}, []string{"/Library/LaunchDaemons", "/Library/LaunchAgents"}, []string{"/private/etc/zshenv", "/private/etc/zprofile", "/private/etc/zshrc", "/private/etc/zlogin", "/private/etc/zlogout"})
}
func scanIOC(ctx context.Context, r Runner, rules []Rule, tmpDirs, launchDirs, shellFiles []string) Check {
	c := Check{Name: "ioc", Status: "ok", Findings: []Finding{}, Data: map[string]any{"rules": len(rules)}}
	if validateRules(rules) != nil {
		return unavailable("ioc", false, "invalid_rules")
	}
	hits := map[string]int{}
	match := func(target, value string) {
		for _, rule := range rules {
			if rule.Target != target {
				continue
			}
			ok := false
			if target == "tmp-name" || target == "launch-name" {
				ok, _ = filepath.Match(rule.Pattern, value)
			} else {
				ok = strings.Contains(value, rule.Pattern)
			}
			if ok {
				hits[rule.ID]++
			}
		}
	}
	for _, s := range []struct {
		target string
		dirs   []string
	}{{"tmp-name", tmpDirs}, {"launch-name", launchDirs}} {
		for _, dir := range s.dirs {
			if ctx.Err() != nil {
				c.Status = "partial"
				continue
			}
			if !safeParents(filepath.Join(dir, "child")) {
				c.Status = "partial"
				continue
			}
			f, err := os.Open(dir)
			if err != nil {
				c.Status = "partial"
				continue
			}
			entries, err := f.ReadDir(maxEntries + 1)
			f.Close()
			if err != nil && err != io.EOF || len(entries) > maxEntries {
				c.Status = "partial"
			}
			for _, e := range entries {
				if !excluded(e.Name()) {
					match(s.target, e.Name())
				}
			}
		}
	}
	for _, path := range shellFiles {
		if !safeParents(path) {
			c.Status = "partial"
			continue
		}
		data, err := readFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			c.Status = "partial"
			continue
		}
		match("shell-content", string(data))
	}
	data, err := r.Run(ctx, "/usr/sbin/lsof", "-nP", "-i", "-Fpn")
	if err != nil {
		c.Status = "partial"
	} else {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "n") {
				match("network", line[1:])
			}
		}
	}
	for _, rule := range rules {
		if count := hits[rule.ID]; count > 0 {
			c.Findings = append(c.Findings, finding(c.Name, "critical", "ioc_match", "Indicator "+rule.ID+" matched bounded evidence."))
		}
	}
	c.Data["matches"] = hits
	c.Findings = append(c.Findings, finding(c.Name, "info", "ioc_limits", "Fixed name/shell/visible-network sweep only. Encrypted C2, processes, nested temporary payloads, sudoers and root SSH-key content are outside coverage. Numeric lsof cannot attribute unresolved pool domains."))
	return c
}
