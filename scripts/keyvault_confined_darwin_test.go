//go:build darwin && cgo

package scripts_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The supported wrapper denies the canary before Go init; the init fallback
// records external confinement, rather than silently accepting any sandbox.
func TestKeyvaultConfinedWrapper(t *testing.T) {
	for _, gate := range []string{"1", "default"} {
		t.Run(gate, func(t *testing.T) {
			cmd := exec.Command("./keyvault-test-confined.sh", "-count=1", "-v", "-tags=keyvault_gate_regression", "-run", "^TestSandboxCanary$", "../internal/keyvault/keychaingate")
			// Omitting the gate exercises the wrapper's default. Both executions
			// enter go test with the gate set and only perform read-only lookups.
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "MAC_KEYVAULT_SKIP_KEYCHAIN=") {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			if gate != "default" {
				cmd.Env = append(cmd.Env, "MAC_KEYVAULT_SKIP_KEYCHAIN="+gate)
			}
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("wrapper canary: %v\n%s", err, output)
			}
			for _, want := range []string{"keychaingate.Applied()=false keychaingate.Confined()=true", "OSStatus -50", "--- PASS: TestSandboxCanary"} {
				if !strings.Contains(string(output), want) {
					t.Fatalf("missing %q:\n%s", want, output)
				}
			}
			t.Logf("%s", output)
		})
	}
}

// A permissive external sandbox makes sandbox_init fail but does not deny the
// read-only lookup. The gate must exit non-zero before the canary test starts.
// This control does not create, change, delete or sign any Keychain item.
func TestKeyvaultConfinedFailClosed(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "canary.test")
	build := exec.Command("go", "test", "-c", "-tags=keyvault_gate_regression", "-o", binary, "../internal/keyvault/keychaingate")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build canary: %v\n%s", err, output)
	}
	cmd := exec.Command("/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)", binary, "-test.v", "-test.run=^TestSandboxCanary$")
	cmd.Env = append(os.Environ(), "MAC_KEYVAULT_SKIP_KEYCHAIN=1")
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("expected gate exit 1, got %v:\n%s", err, output)
	}
	text := string(output)
	if !strings.Contains(text, "sandbox_init:") || !strings.Contains(text, "read-only canary OSStatus") || !strings.Contains(text, "refusing to run unsandboxed") || strings.Contains(text, "=== RUN") || strings.Contains(text, "canary OSStatus -50;") {
		t.Fatalf("expected fail-closed init before tests, got:\n%s", output)
	}
	t.Logf("expected init refusal: %s", output)
}
