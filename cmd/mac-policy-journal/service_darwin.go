package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/relux-works/mac-infra/internal/policyjournal"
)

const label = "works.relux.mac-infra-claude-policy-journal"

// Refuse pre-existing aliases before creating descendants. This is not an
// isolation boundary against a hostile concurrent same-UID directory swap.
func makeDirectories(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return fmt.Errorf("absolute clean directory required")
	}
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		current = filepath.Join(current, part)
		i, e := os.Lstat(current)
		if os.IsNotExist(e) {
			if e = os.Mkdir(current, 0700); e != nil {
				return e
			}
			continue
		}
		if e != nil {
			return e
		}
		if !i.IsDir() || i.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("directory alias refused")
		}
	}
	return nil
}

func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
func servicePlist(exe, home, dir string, extra []string) string {
	args := []string{exe, "run", "--user-root", home, "--journal", filepath.Join(dir, "events.jsonl"), "--rescan", "30s"}
	for _, p := range extra {
		args = append(args, "--home", p)
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>Label</key><string>` + label + `</string><key>ProgramArguments</key><array>`)
	for _, a := range args {
		b.WriteString("<string>" + xmlText(a) + "</string>")
	}
	b.WriteString(`</array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>30</integer><key>StandardOutPath</key><string>` + xmlText(filepath.Join(dir, "service.log")) + `</string><key>StandardErrorPath</key><string>` + xmlText(filepath.Join(dir, "service.log")) + `</string></dict></plist>`)
	return b.String()
}

func service(args []string, out io.Writer) int {
	h, e := os.UserHomeDir()
	if e != nil {
		fmt.Fprintln(out, "user home unavailable")
		return 1
	}
	dir := filepath.Join(h, "Library", "Application Support", "mac-infra", "claude-policy-journal")
	plist := filepath.Join(h, "Library", "LaunchAgents", label+".plist")
	domain := "gui/" + strconv.Itoa(os.Getuid())
	job := domain + "/" + label
	if len(args) == 1 && args[0] == "status" {
		data, e := exec.Command("/bin/launchctl", "print", job).Output()
		if e != nil {
			fmt.Fprintln(out, "not_loaded")
			return 1
		}
		fmt.Fprintln(out, "loaded")
		for _, line := range strings.Split(string(data), "\n") {
			s := strings.TrimSpace(line)
			if strings.HasPrefix(s, "pid = ") {
				if pid, e := strconv.Atoi(strings.TrimPrefix(s, "pid = ")); e == nil {
					fmt.Fprintf(out, "pid=%d\n", pid)
				}
			}
		}
		return 0
	}
	if len(args) == 1 && args[0] == "disable" {
		if e = exec.Command("/bin/launchctl", "bootout", job).Run(); e != nil {
			fmt.Fprintln(out, "bootout failed; journal retained")
			return 1
		}
		// Preserve the plist and all records; enable never overwrites them.
		fmt.Fprintln(out, "stopped; plist and journal retained")
		return 0
	}
	if len(args) < 1 || args[0] != "enable" {
		fmt.Fprintln(out, "invalid service command")
		return 2
	}
	var extra paths
	for i := 1; i < len(args); i += 2 {
		if args[i] != "--home" || i+1 == len(args) || extra.Set(args[i+1]) != nil {
			fmt.Fprintln(out, "invalid additional home")
			return 2
		}
	}
	if _, e = os.Lstat(plist); !os.IsNotExist(e) {
		fmt.Fprintln(out, "existing plist retained; use launchctl bootstrap for an existing installation")
		return 1
	}
	if e = makeDirectories(dir); e != nil {
		fmt.Fprintln(out, "private state directory unavailable")
		return 1
	}
	homes, _, _, _ := policyjournal.Discover(policyjournal.OSMetadata{}, h, extra)
	log, e := policyjournal.OpenJournal(filepath.Join(dir, "events.jsonl"), homes)
	if e != nil {
		fmt.Fprintln(out, "private journal preflight refused")
		return 1
	}
	_ = log.Close()
	serviceLog, e := policyjournal.OpenJournal(filepath.Join(dir, "service.log"), homes)
	if e != nil {
		fmt.Fprintln(out, "private service log preflight refused")
		return 1
	}
	_ = serviceLog.Close()
	exe, e := os.Executable()
	if e != nil {
		fmt.Fprintln(out, "executable unavailable")
		return 1
	}
	exe, e = filepath.EvalSymlinks(exe)
	if e != nil {
		fmt.Fprintln(out, "executable unavailable")
		return 1
	}
	if e = makeDirectories(filepath.Dir(plist)); e != nil {
		fmt.Fprintln(out, "LaunchAgents unavailable")
		return 1
	}
	f, e := os.OpenFile(plist, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		fmt.Fprintln(out, "plist creation refused")
		return 1
	}
	_, writeErr := io.WriteString(f, servicePlist(exe, h, dir, extra))
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		fmt.Fprintln(out, "plist write failed; partial artifact retained")
		return 1
	}
	if e = exec.Command("/bin/launchctl", "bootstrap", domain, plist).Run(); e != nil {
		fmt.Fprintln(out, "bootstrap failed; plist and journal retained")
		return 1
	}
	fmt.Fprintln(out, "loaded; verify status and metadata-only baselines in events.jsonl")
	return 0
}
