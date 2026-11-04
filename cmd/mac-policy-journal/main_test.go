//go:build darwin

package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Proves bad arguments fail without an output write, paired with the documented
// help route; errors never echo arbitrary argument content.
func TestOptionsAndHelp(t *testing.T) {
	for _, args := range [][]string{{"run"}, {"run", "--user-root", "relative"}, {"run", "--UNKNOWN_SECRET"}, {"enable", "--home"}} {
		var b bytes.Buffer
		if code := execute(context.Background(), args, &b); code != 2 {
			t.Fatalf("%v: %d %s", args, code, b.String())
		}
		if strings.Contains(b.String(), "UNKNOWN_SECRET") {
			t.Fatal("raw input echoed")
		}
	}
	var b bytes.Buffer
	if execute(context.Background(), []string{"help"}, &b) != 0 || !strings.Contains(b.String(), "Metadata only") {
		t.Fatal(b.String())
	}
}

// Proves the persistent service runs the exact binary/arguments with XML-safe
// paths, fixed label and bounded rescan; no shell/profile/native session launch.
func TestServicePlist(t *testing.T) {
	s := servicePlist("/safe/tool", "/user", "/private/state", []string{"/a&b/<home>"})
	d := xml.NewDecoder(strings.NewReader(s))
	for {
		_, e := d.Token()
		if e != nil {
			if e.Error() != "EOF" {
				t.Fatal(e)
			}
			break
		}
	}
	for _, part := range []string{"<string>/safe/tool</string>", "<string>run</string>", "<string>30s</string>", "/a&amp;b/&lt;home&gt;", label} {
		if !strings.Contains(s, part) {
			t.Fatal(part)
		}
	}
	if strings.Contains(s, "/bin/sh") {
		t.Fatal("shell wrapper")
	}
}

// Proves a finite real observer run produces a private baseline without policy
// content. Test-owned input files only; no live-home or launchd interaction.
func TestFiniteRunMetadataOnly(t *testing.T) {
	r, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	_ = os.Chmod(r, 0700)
	h := filepath.Join(r, ".claude")
	_ = os.Mkdir(h, 0700)
	_ = os.WriteFile(filepath.Join(h, "remote-settings.json"), []byte("FORBIDDEN_SENTINEL"), 0600)
	journal := filepath.Join(r, "journal.jsonl")
	var output bytes.Buffer
	if code := execute(context.Background(), []string{"run", "--user-root", r, "--journal", journal, "--rescan", "1s", "--duration", "100ms"}, &output); code != 0 {
		t.Fatalf("%d %s", code, output.String())
	}
	data, e := os.ReadFile(journal)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(data, []byte("FORBIDDEN_SENTINEL")) || !bytes.Contains(data, []byte(`"state":"present"`)) || !bytes.Contains(data, []byte(`"kind":"observer_stop"`)) {
		t.Fatal(string(data))
	}
}

// Proves service-directory preparation refuses an alias before creating any
// descendant outside the declared tree, paired with a valid private directory.
func TestServiceDirectoryNoAlias(t *testing.T) {
	r, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	valid := filepath.Join(r, "state", "journal")
	if e = makeDirectories(valid); e != nil {
		t.Fatal(e)
	}
	alias := filepath.Join(r, "alias")
	if e = os.Symlink(filepath.Join(r, "state"), alias); e != nil {
		t.Fatal(e)
	}
	if makeDirectories(filepath.Join(alias, "forbidden")) == nil {
		t.Fatal("alias admitted")
	}
	if _, e = os.Stat(filepath.Join(r, "state", "forbidden")); !os.IsNotExist(e) {
		t.Fatal("forbidden descendant created")
	}
}

// Proves the review reproductions now fail closed: --journal as an uppercase
// alias of either monitored policy file exits 1 and leaves the policy byte-for-
// byte unchanged, while a separate private journal exits 0 with the same policy
// unchanged.
func TestRunRefusesPolicyCaseAliasJournal(t *testing.T) {
	r, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	_ = os.Chmod(r, 0700)
	h := filepath.Join(r, ".claude")
	_ = os.Mkdir(h, 0700)
	for _, n := range []string{"remote-settings.json", "policy-limits.json"} {
		_ = os.WriteFile(filepath.Join(h, n), []byte(`{"synthetic":"policy"}`), 0600)
	}
	check := func(label string) {
		t.Helper()
		for _, n := range []string{"remote-settings.json", "policy-limits.json"} {
			if data, e := os.ReadFile(filepath.Join(h, n)); e != nil || string(data) != `{"synthetic":"policy"}` {
				t.Fatalf("%s: %s changed: %q", label, n, data)
			}
		}
	}
	for _, alias := range []string{"REMOTE-SETTINGS.JSON", "POLICY-LIMITS.JSON"} {
		var b bytes.Buffer
		if code := execute(context.Background(), []string{"run", "--user-root", r, "--journal", filepath.Join(h, alias), "--rescan", "1s", "--duration", "10ms"}, &b); code != 1 {
			t.Fatalf("%s: exit %d %s", alias, code, b.String())
		}
		check(alias)
	}
	var b bytes.Buffer
	if code := execute(context.Background(), []string{"run", "--user-root", r, "--journal", filepath.Join(r, "events.jsonl"), "--rescan", "1s", "--duration", "10ms"}, &b); code != 0 {
		t.Fatalf("separate journal: exit %d %s", code, b.String())
	}
	check("separate journal")
}

// Proves an explicitly requested absent home is visible: exit 0 with a
// home_absent record for that path, paired with a present declared home that is
// baselined in the same run.
func TestRunReportsMissingDeclaredHome(t *testing.T) {
	r, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	_ = os.Chmod(r, 0700)
	_ = os.Mkdir(filepath.Join(r, ".claude"), 0700)
	present := filepath.Join(r, "present-home")
	_ = os.Mkdir(present, 0700)
	missing := filepath.Join(r, "explicit-home")
	journal := filepath.Join(r, "events.jsonl")
	var b bytes.Buffer
	if code := execute(context.Background(), []string{"run", "--user-root", r, "--journal", journal, "--rescan", "1s", "--duration", "100ms", "--home", missing, "--home", present}, &b); code != 0 {
		t.Fatalf("exit %d %s", code, b.String())
	}
	data, e := os.ReadFile(journal)
	if e != nil {
		t.Fatal(e)
	}
	s := string(data)
	if !strings.Contains(s, `"kind":"home_absent","home":"`+missing+`"`) || !strings.Contains(s, `"home":"`+present+`"`) {
		t.Fatal(s)
	}
}
