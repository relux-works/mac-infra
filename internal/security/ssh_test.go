package security

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Current-user ForwardAgent yes and included declarations are flagged; no
// declarations are fabricated for a valid no configuration. Key/comments and
// command error details are suppressed, and unauthorized Includes stay partial.
func TestSSHHygieneDeclarationsAndSecretSuppression(t *testing.T) {
	home := fixtureDir(t)
	dir := filepath.Join(home, ".ssh")
	os.Mkdir(dir, 0700)
	config := filepath.Join(dir, "config")
	os.WriteFile(config, []byte("ForwardAgent no\n"), 0600)
	r := coreFakeRunner{[]byte("256 SHA256:fake secret-agent-comment (ED25519)\n"), nil}
	c := scanSSH(context.Background(), r, home, "", "")
	if c.Data["forward_agent_declarations"] != 0 || c.Data["agent_key_count"] != 1 {
		t.Fatal(c)
	}
	os.Mkdir(filepath.Join(dir, "config.d"), 0700)
	os.WriteFile(filepath.Join(dir, "config.d/extra.conf"), []byte("ForwardAgent=yes\n"), 0600)
	os.WriteFile(config, []byte("Include extra\nForwardAgent yes\nInclude /other/private/config\n"), 0600)
	c = scanSSH(context.Background(), r, home, "", "")
	if c.Data["forward_agent_declarations"] != 2 || c.Status != "partial" {
		t.Fatal(c)
	}
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), "secret-agent-comment") || strings.Contains(string(b), "SHA256:fake") {
		t.Fatal("agent data leaked")
	}
	c = scanSSH(context.Background(), coreFakeRunner{err: errors.New("private-error")}, home, "", "")
	b, _ = json.Marshal(c)
	if c.Status != "partial" || strings.Contains(string(b), "private-error") {
		t.Fatal(c)
	}
}

// Include never opens a private-key-shaped source or expands arbitrary globs;
// a nearby direct ForwardAgent declaration still receives the warning.
func TestSSHDoesNotExpandPrivateKeyInclude(t *testing.T) {
	home := fixtureDir(t)
	dir := filepath.Join(home, ".ssh")
	os.Mkdir(dir, 0700)
	os.WriteFile(filepath.Join(dir, "id_ed25519"), []byte("ForwardAgent yes\n"), 0600)
	os.WriteFile(filepath.Join(dir, "config"), []byte("Include id_ed25519\nInclude *\nForwardAgent no\n"), 0600)
	c := scanSSH(context.Background(), coreFakeRunner{}, home, "", "")
	if c.Data["forward_agent_declarations"] != 0 || c.Status != "partial" {
		t.Fatal(c)
	}
	os.WriteFile(filepath.Join(dir, "config"), []byte("ForwardAgent yes\n"), 0600)
	c = scanSSH(context.Background(), coreFakeRunner{}, home, "", "")
	if c.Data["forward_agent_declarations"] != 1 {
		t.Fatal(c)
	}
}

// Symlinked config.d sources are missing coverage, while a legitimate absent
// directory with safe parents does not invent an Include failure.
func TestSSHUnsafeConfigDirectoryPartial(t *testing.T) {
	home := fixtureDir(t)
	dir := filepath.Join(home, ".ssh")
	os.Mkdir(dir, 0700)
	os.WriteFile(filepath.Join(dir, "config"), []byte("ForwardAgent no\n"), 0600)
	runner := coreFakeRunner{data: []byte("256 SHA256:fixture comment\n")}
	c := scanSSH(context.Background(), runner, home, "", "")
	if c.Status != "ok" {
		t.Fatal(c)
	}
	os.Symlink(fixtureDir(t), filepath.Join(dir, "config.d"))
	c = scanSSH(context.Background(), runner, home, "", "")
	if c.Status != "partial" {
		t.Fatal(c)
	}
}
