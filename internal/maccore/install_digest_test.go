package maccore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: install announces the snapshot digest before any sudo call, and a
// digest that differs from the expected one stops it before sudo. Positive
// control: the matching digest passes the gate and reaches the sudo step.
func TestInstallDigestGateRunsBeforeSudo(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "mac-infra-core")
	content := []byte("#!/bin/sh\nexit 0\n")
	if err := os.WriteFile(binary, content, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	var sudoCalls []string
	original := execCommandCore
	execCommandCore = func(name string, args ...string) *exec.Cmd {
		sudoCalls = append(sudoCalls, name+" "+strings.Join(args, " "))
		return exec.Command("/usr/bin/false")
	}
	t.Cleanup(func() { execCommandCore = original })

	var announced string
	err := InstallService(DefaultServiceConfig(), binary, 501, 20, InstallOptions{
		ExpectedSHA256: strings.Repeat("0", 64),
		Announce:       func(_ string, sha string, _ int) { announced = sha },
	})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched digest error = %v", err)
	}
	if announced != digest || len(sudoCalls) != 0 {
		t.Fatalf("announced %q (want %q), sudo calls %v", announced, digest, sudoCalls)
	}
	if got, size, err := ReviewedExecutableDigest(binary); err != nil || got != digest || size != len(content) {
		t.Fatalf("ReviewedExecutableDigest = %q %d %v", got, size, err)
	}

	err = InstallService(DefaultServiceConfig(), binary, 501, 20, InstallOptions{ExpectedSHA256: strings.ToUpper(digest)})
	if err == nil || !strings.Contains(err.Error(), "sudo") || len(sudoCalls) == 0 {
		t.Fatalf("control: matching digest error = %v, sudo calls %v", err, sudoCalls)
	}
}

// Claim: the daemon refuses a request carrying an unknown field (for
// example a smuggled command) instead of ignoring it; the same request
// without that field is served.
func TestDaemonRefusesUnknownRequestFields(t *testing.T) {
	socketPath := tempSocketPath(t, "mic-strict")
	cfg := ServiceConfig{Label: "works.relux.test-core", SocketPath: socketPath}
	errCh := make(chan error, 1)
	go func() {
		errCh <- (serviceDaemon{cfg: cfg, clientUID: os.Getuid(), clientGID: os.Getgid()}).serve()
	}()
	waitForSocket(t, cfg, errCh)

	send := func(raw string) Response {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte(raw + "\n")); err != nil {
			t.Fatal(err)
		}
		var response Response
		if err := json.NewDecoder(conn).Decode(&response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	if response := send(`{"action":"ping","command":"/bin/sh"}`); response.OK || !strings.Contains(response.Error, "unknown field") {
		t.Fatalf("unknown field response = %+v", response)
	}
	if response := send(`{"action":"ping"}`); !response.OK {
		t.Fatalf("control ping response = %+v", response)
	}
}
