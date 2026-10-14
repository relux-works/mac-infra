package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/mac-infra/internal/keyvault"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// CLI validation refuses missing/unpinned identities and invalid hook
// options before opening the backend. Adjacent valid pub output is parseable.
func TestRunSSHAgentArgumentsAndPublicKey(t *testing.T) {
	store := newMemStore(tl("ssh-agent", 1))
	old := newBackend
	newBackend = func() keyvault.Backend { return store }
	defer func() { newBackend = old }()
	for _, args := range [][]string{
		{}, {"--socket", "/tmp/test.sock"}, {"--socket", "/tmp/test.sock", "--key", "test/ssh-agent"},
		{"--socket", "/tmp/test.sock", "--key", "test/ssh-agent@0"}, {"--socket", "/tmp/test.sock", "--key", "test/ssh-agent@1", "--confirm-arg", "x"},
		{"--socket", "/tmp/test.sock", "--key", "test/ssh-agent@1", "--confirm-exec", "relative"},
	} {
		var out, err bytes.Buffer
		code := run(append([]string{"--json", "ssh-agent"}, args...), &out, &err)
		if code != exitUsage || err.Len() != 0 {
			t.Fatalf("args %v: %d %s %s", args, code, &out, &err)
		}
	}
	if store.touched() {
		t.Fatal("invalid flags opened vault")
	}
	var out, err bytes.Buffer
	if code := run([]string{"pub", "test/ssh-agent", "--version", "1", "--format", "ssh"}, &out, &err); code != 0 {
		t.Fatalf("pub: %d %s", code, &err)
	}
	key, _, _, _, parseErr := ssh.ParseAuthorizedKey(out.Bytes())
	if parseErr != nil || key.Type() != ssh.KeyAlgoECDSA256 {
		t.Fatalf("public SSH output: %v", parseErr)
	}
	out.Reset()
	err.Reset()
	if code := run([]string{"--json", "pub", "test/ssh-agent", "--version", "1", "--format", "ssh"}, &out, &err); code != 0 {
		t.Fatalf("json pub: %d %s", code, &out)
	}
	var response struct{ Result map[string]any }
	if json.Unmarshal(out.Bytes(), &response) != nil || !strings.HasPrefix(response.Result["ssh"].(string), ssh.KeyAlgoECDSA256) {
		t.Fatal("SSH pub envelope missing public output")
	}
}

// The process-level helper uses a memory backend only; no user keychain or
// live configuration is accessed during daemon lifecycle verification.
func TestSSHAgentCLIHelper(t *testing.T) {
	if os.Getenv("MAC_KEYVAULT_SSH_HELPER") != "1" {
		return
	}
	store := newMemStore(tl("ssh-agent", 1))
	newBackend = func() keyvault.Backend { return store }
	lockPath = func() (string, error) { return filepath.Join(os.Getenv("MAC_KEYVAULT_SSH_HELPER_DIR"), "lock"), nil }
	os.Exit(run([]string{"ssh-agent", "--socket", os.Getenv("MAC_KEYVAULT_SSH_HELPER_SOCKET"), "--key", "test/ssh-agent@1"}, os.Stdout, os.Stderr))
}

// The actual CLI serves identities, handles SIGTERM cleanly and removes its
// socket. A pre-existing path is refused without overwriting its content.
func TestRunSSHAgentLifecycle(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "kv-cli-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "agent.sock")
	var logs bytes.Buffer
	cmd := exec.Command(os.Args[0], "-test.run=^TestSSHAgentCLIHelper$")
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "MAC_KEYVAULT_SSH_HELPER=1", "MAC_KEYVAULT_SSH_HELPER_DIR=" + dir, "MAC_KEYVAULT_SSH_HELPER_SOCKET=" + socket}
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	var conn net.Conn
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.Dial("unix", socket)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if conn == nil {
		t.Fatal("CLI did not create socket")
	}
	defer conn.Close()
	keys, err := agent.NewClient(conn).List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("CLI identities: %v %v", keys, err)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("CLI shutdown: %v %s", err, &logs)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("CLI shutdown timed out")
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatal("CLI socket survived shutdown")
	}
	os.WriteFile(socket, []byte("foreign"), 0600)
	logs.Reset()
	next := exec.Command(os.Args[0], "-test.run=^TestSSHAgentCLIHelper$")
	next.Env = cmd.Env
	next.Stdout = &logs
	next.Stderr = &logs
	if err := next.Run(); err == nil {
		t.Fatal("CLI replaced foreign file")
	}
	content, _ := os.ReadFile(socket)
	if string(content) != "foreign" {
		t.Fatal("foreign path changed")
	}
}
