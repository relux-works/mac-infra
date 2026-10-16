//go:build darwin && !cgo

package maccore

import (
	"os/exec"
	"strings"
	"testing"
)

// A build without native ACL support refuses installation before any privileged
// command. This control does not execute sudo or inspect a live service.
func TestTrustUnavailableRefusesBeforePrivilege(t *testing.T) {
	old := execCommandCore
	execCommandCore = func(name string, args ...string) *exec.Cmd {
		t.Fatalf("command after unsupported trust check: %s", name)
		return nil
	}
	t.Cleanup(func() { execCommandCore = old })
	err := InstallService(DefaultServiceConfig(), "/not-opened", 501, 20, InstallOptions{})
	if err == nil || !strings.Contains(err.Error(), "cgo ACL support") {
		t.Fatalf("error=%v, want unavailable native ACL check", err)
	}
}
