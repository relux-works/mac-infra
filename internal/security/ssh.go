package security

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// SSH reports declarations, not the effective configuration for any target.
// Only fixed config and config.d/*.conf sources are inspected; Includes are
// reported as incomplete rather than expanded into arbitrary file reads. It never
// reads private key files or returns public keys, comments, hosts or raw lines.
func SSH(ctx context.Context, r Runner, home string) Check {
	return scanSSH(ctx, r, home, "/private/etc/ssh/ssh_config", "/private/var/root/.ssh/authorized_keys")
}
func scanSSH(ctx context.Context, r Runner, home, systemConfig, rootAuthorized string) Check {
	c := Check{Name: "ssh", Status: "ok", Findings: []Finding{}, Data: map[string]any{}}
	seen := map[string]bool{}
	forward := 0

	var scan func(string, int)
	scan = func(path string, depth int) {
		if ctx.Err() != nil || depth > 8 || len(seen) >= 128 {
			c.Status = "partial"
			return
		}
		if seen[path] {
			return
		}
		seen[path] = true
		if excluded(path) || !safeParents(path) {
			c.Status = "partial"
			return
		}
		data, err := readFile(path)
		if os.IsNotExist(err) {
			return
		}
		if err != nil {
			c.Status = "partial"
			return
		}
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		for sc.Scan() {
			line := strings.TrimSpace(strings.SplitN(sc.Text(), "#", 2)[0])
			f := strings.Fields(strings.ReplaceAll(line, "=", " "))
			if len(f) < 2 {
				continue
			}
			if strings.EqualFold(f[0], "ForwardAgent") && !strings.EqualFold(f[1], "no") {
				forward++
				c.Findings = append(c.Findings, finding(c.Name, "warning", "forward_agent", "A ForwardAgent declaration enables or selects agent forwarding; review target-specific effective configuration."))
			}
			if strings.EqualFold(f[0], "Include") {
				c.Status = "partial"
			}

		}
		if sc.Err() != nil {
			c.Status = "partial"
		}
	}
	scan(filepath.Join(home, ".ssh/config"), 0)
	if systemConfig != "" {
		scan(systemConfig, 0)
	}
	for _, dir := range []string{filepath.Join(home, ".ssh/config.d"), filepath.Join(filepath.Dir(systemConfig), "ssh_config.d")} {
		if systemConfig == "" && dir == "ssh_config.d" {
			continue
		}
		if !safeParents(filepath.Join(dir, "child")) {
			if _, e := os.Lstat(dir); !os.IsNotExist(e) || !safeParents(dir) {
				c.Status = "partial"
			}
			continue
		}
		f, e := os.Open(dir)
		if e != nil {
			if !os.IsNotExist(e) {
				c.Status = "partial"
			}
			continue
		}
		entries, e := f.ReadDir(129)
		f.Close()
		if e != nil && e != io.EOF || len(entries) > 128 {
			c.Status = "partial"
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".conf") {
				scan(filepath.Join(dir, entry.Name()), 0)
			}
		}
	}
	c.Data["forward_agent_declarations"] = forward
	c.Data["config_files_seen"] = len(seen)
	for _, s := range []struct {
		name, path string
		root       bool
	}{{"current_user_authorized_keys", filepath.Join(home, ".ssh/authorized_keys"), false}, {"root_authorized_keys", rootAuthorized, true}} {
		// Presence inspection only: never open authorized_keys for SSH hygiene.
		if s.path == "" {
			c.Data[s.name] = "outside_fixture"
			continue
		}
		_, err := os.Lstat(s.path)
		state := "present"
		if os.IsNotExist(err) {
			state = "absent"
		} else if err != nil {
			state = "unavailable"
			c.Status = "partial"
		}
		c.Data[s.name] = state
		if s.root && state == "unavailable" {
			c.Findings = append(c.Findings, finding(c.Name, "info", "root_required", "Root authorized_keys presence cannot be established with current permissions."))
			c.RequiresRoot = true
		}
	}
	data, err := r.Run(ctx, "/usr/bin/ssh-add", "-l")
	if err != nil {
		c.Data["agent"] = "unavailable"
		c.Status = "partial"
	} else {
		count := 0
		valid := true
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 || !strings.HasPrefix(f[1], "SHA256:") {
				valid = false
				break
			}
			count++
		}
		if valid {
			c.Data["agent_key_count"] = count
		} else {
			c.Data["agent"] = "unavailable"
			c.Status = "partial"
		}
	}
	c.Findings = append(c.Findings, finding(c.Name, "info", "ssh_limits", "Declarations are not target-specific effective settings; Includes, Match evaluation and other users are outside coverage. Agent comments are suppressed because comments may contain secrets."))
	return c
}
