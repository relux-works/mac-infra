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
	"sync"
	"testing"
	"time"
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
	preflight := func(string) error { return nil } // No host installation paths are accessed by this digest-gate test.
	err := installServiceWithPreflight(DefaultServiceConfig(), binary, 501, 20, InstallOptions{
		ExpectedSHA256: strings.Repeat("0", 64),
		Announce:       func(_ string, sha string, _ int) { announced = sha },
	}, preflight)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched digest error = %v", err)
	}
	if announced != digest || len(sudoCalls) != 0 {
		t.Fatalf("announced %q (want %q), sudo calls %v", announced, digest, sudoCalls)
	}
	if got, size, err := ReviewedExecutableDigest(binary); err != nil || got != digest || size != len(content) {
		t.Fatalf("ReviewedExecutableDigest = %q %d %v", got, size, err)
	}

	err = installServiceWithPreflight(DefaultServiceConfig(), binary, 501, 20, InstallOptions{ExpectedSHA256: strings.ToUpper(digest)}, preflight)
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

// Claim: a request larger than maxRequestBytes is refused even when it is a
// valid ping padded with whitespace, which an unbounded reader would serve;
// the same ping without padding is served (control).
func TestDaemonRefusesOversizedRequest(t *testing.T) {
	socketPath := tempSocketPath(t, "mic-big")
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
		go func() { _, _ = conn.Write([]byte(raw)) }()
		var response Response
		if err := json.NewDecoder(conn).Decode(&response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	if response := send(`{"action":"ping"` + strings.Repeat(" ", maxRequestBytes) + `}`); response.OK || response.Error == "" {
		t.Fatalf("oversized request response = %+v", response)
	}
	if response := send(`{"action":"ping"}`); !response.OK {
		t.Fatalf("control ping response = %+v", response)
	}
}

func pingOnce(socketPath string) bool {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte(`{"action":"ping"}` + "\n")); err != nil {
		return false
	}
	var response Response
	return json.NewDecoder(conn).Decode(&response) == nil && response.OK
}

func eventuallyPings(socketPath string, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if pingOnce(socketPath) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// Claim: the daemon serves at most maxConnections requests at once and
// closes further connections unread; a slot freed by a client is reused
// (control).
func TestDaemonCapsConcurrentConnections(t *testing.T) {
	socketPath := tempSocketPath(t, "mic-cap")
	cfg := ServiceConfig{Label: "works.relux.test-core", SocketPath: socketPath}
	errCh := make(chan error, 1)
	go func() {
		errCh <- (serviceDaemon{cfg: cfg, clientUID: os.Getuid(), clientGID: os.Getgid()}).serve()
	}()
	waitForSocket(t, cfg, errCh)
	var idle []net.Conn
	for i := 0; i < maxConnections; i++ {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			t.Fatal(err)
		}
		idle = append(idle, conn)
	}
	if pingOnce(socketPath) {
		t.Fatal("a connection beyond the cap was served")
	}
	for _, conn := range idle {
		_ = conn.Close()
	}
	if !eventuallyPings(socketPath, 3*time.Second) {
		t.Fatal("control: no slot was freed after the idle clients left")
	}
}

// Claim: clients whose requests were fully read but who never read their
// large responses hold every slot (a new ping is refused), and the write
// deadline then frees the slots so a new ping is served. Bounded control:
// with SetWriteDeadline removed this test fails (mutation-03.log, M6).
func TestDaemonFreesSlotsOfStalledReaders(t *testing.T) {
	socketPath := tempSocketPath(t, "mic-stall")
	cfg := ServiceConfig{Label: "works.relux.test-core", SocketPath: socketPath}
	errCh := make(chan error, 1)
	go func() {
		errCh <- (serviceDaemon{cfg: cfg, clientUID: os.Getuid(), clientGID: os.Getgid(), writeTimeout: time.Second}).serve()
	}()
	waitForSocket(t, cfg, errCh)
	// The echoed unknown action makes a response far larger than the socket
	// buffers, so an unread response blocks the handler in its write.
	request := []byte(`{"action":"` + strings.Repeat("x", 200<<10) + `"}` + "\n")
	var written sync.WaitGroup
	for i := 0; i < maxConnections; i++ {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		written.Add(1)
		go func() {
			defer written.Done()
			_, _ = conn.Write(request)
		}()
	}
	written.Wait()
	if pingOnce(socketPath) {
		t.Fatal("a ping was served while every slot should be blocked writing")
	}
	if !eventuallyPings(socketPath, 5*time.Second) {
		t.Fatal("stalled readers kept every slot")
	}
}
