package maccore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenderServicePlistContainsDaemonArguments(t *testing.T) {
	cfg := ServiceConfig{
		Label:      "works.relux.test-core",
		PlistPath:  "/Library/LaunchDaemons/works.relux.test-core.plist",
		SocketPath: "/var/run/works.relux.test-core.sock",
	}

	plist := string(RenderServicePlist(cfg, "/tmp/mac-infra-core", 501, 20))

	for _, want := range []string{
		"<string>works.relux.test-core</string>",
		"<string>/tmp/mac-infra-core</string>",
		"<string>_daemon</string>",
		"<string>/var/run/works.relux.test-core.sock</string>",
		"<string>501</string>",
		"<string>20</string>",
		"<key>KeepAlive</key>",
	} {
		if !strings.Contains(plist, want) {
			t.Fatalf("plist missing %q:\n%s", want, plist)
		}
	}
}

func TestDaemonPing(t *testing.T) {
	socketPath := tempSocketPath(t, "mac-infra-core")
	cfg := ServiceConfig{Label: "works.relux.test-core", SocketPath: socketPath}
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunDaemon(cfg, os.Getuid(), os.Getgid())
	}()
	waitForSocket(t, cfg, errCh)

	resp, err := Call(cfg, Request{Action: "ping"})
	if err != nil {
		t.Fatalf("Call ping error = %v", err)
	}
	if !resp.OK || resp.DaemonPID <= 0 {
		t.Fatalf("ping response = %#v, want ok with daemon pid", resp)
	}
}

func TestDaemonRejectsUnsupportedAction(t *testing.T) {
	socketPath := tempSocketPath(t, "mac-infra-core-unsupported")
	cfg := ServiceConfig{Label: "works.relux.test-core", SocketPath: socketPath}
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunDaemon(cfg, os.Getuid(), os.Getgid())
	}()
	waitForSocket(t, cfg, errCh)

	_, err := Call(cfg, Request{Action: "run_arbitrary_command"})
	if err == nil {
		t.Fatal("Call unsupported action error = nil, want error")
	}
	if !strings.Contains(err.Error(), "unsupported mac-infra-core action") {
		t.Fatalf("unsupported action error = %q", err)
	}
}

func tempSocketPath(t *testing.T, prefix string) string {
	t.Helper()
	path := filepath.Join(os.TempDir(), fmt.Sprintf("%s-%d.sock", prefix, time.Now().UnixNano()))
	_ = os.Remove(path)
	t.Cleanup(func() {
		_ = os.Remove(path)
	})
	return path
}

func waitForSocket(t *testing.T, cfg ServiceConfig, errCh <-chan error) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("daemon exited early: %v", err)
		default:
		}
		status, err := InspectService(cfg)
		if err != nil {
			t.Fatalf("InspectService error = %v", err)
		}
		if status.Reachable {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("socket %s did not become reachable", cfg.SocketPath)
}
