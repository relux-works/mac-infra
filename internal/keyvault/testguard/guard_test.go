package testguard

import (
	"strings"
	"testing"
)

// An ungated call, alias, zero-value backend, launcher or C bridge is rejected without executing it.
func TestCheckSourceRejectsUngatedBackend(t *testing.T) {
	for _, body := range []string{
		`func TestLeak(t *testing.T) { NewSecurityStore() }`,
		`var constructor = keyvault.NewSecurityStore`,
		`var store = &SecurityStore{}`,
		`var store keyvault.SecurityStore`,
		`func TestLeak(t *testing.T) { keyvault.DefaultEnclaveStore() }`,
		`var helper = keyvault.ExecEnclaveHelper{}`,
		`func TestLeak(t *testing.T) { C.MacKeyVaultCreate() }`,
	} {
		t.Run(body, func(t *testing.T) {
			err := CheckSource("internal/keyvault/planted_test.go", []byte("package keyvault\n"+body))
			if err == nil || !strings.Contains(err.Error(), "outside a gated helper") {
				t.Fatalf("guard verdict: %v", err)
			}
		})
	}
}

// Only the registered helper with a leading gate may construct a real backend.
func TestCheckSourceRequiresLeadingGate(t *testing.T) {
	for _, tc := range []struct {
		body string
		safe bool
	}{
		{`testguard.Require(t); return NewSecurityStore()`, true},
		{`t.Helper(); testguard.Require(t); return NewSecurityStore()`, true},
		{`return NewSecurityStore()`, false},
		{`store := NewSecurityStore(); testguard.Require(t); return store`, false},
	} {
		source := []byte("package keyvault\nfunc newGuardedSecurityStore(t *testing.T) *SecurityStore {" + tc.body + "}")
		err := CheckSource("internal/keyvault/security_darwin_test.go", source)
		if (err == nil) != tc.safe {
			t.Fatalf("%s: %v", tc.body, err)
		}
	}
}

// Every non-empty value enables the gate; the empty value leaves explicit integration runs available.
func TestEnabled(t *testing.T) {
	for _, value := range []string{"", "1", "0", "false"} {
		t.Setenv(SkipEnv, value)
		if Enabled() != (value != "") {
			t.Fatalf("gate for %q", value)
		}
	}
}
