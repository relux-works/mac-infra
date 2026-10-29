//go:build darwin && cgo

package keyvault

import (
	"errors"
	"os"
	"testing"

	"github.com/relux-works/mac-infra/internal/keyvault/keychaingate"
)

var initSandboxApplied bool
var initSandboxItems []Item
var initSandboxError error

func init() {
	if os.Getenv(keychaingate.SkipEnv) != "" {
		initSandboxApplied = keychaingate.Applied()
		initSandboxItems, initSandboxError = NewSecurityStore().List()
	}
}

func assertSandboxListRefused(t *testing.T, items []Item, err error, applied bool) {
	t.Helper()
	var status *StatusError
	if len(items) != 0 || !errors.As(err, &status) || status.Status != -50 {
		t.Fatalf("expected no items and sandbox OSStatus -50, got %d items, %v", len(items), err)
	}
	t.Logf("in-process=%t; read-only List refused: %v; no write attempted", applied, err)
	if !applied {
		t.Fatal("in-process sandbox was not installed before backend access")
	}
}

func requireSandboxRegression(t *testing.T) {
	t.Helper()
	if os.Getenv(keychaingate.SkipEnv) == "" {
		t.Skip("requires the init sandbox")
	}
}

// The imported sandbox is installed before a test-file init's first Security.framework contact.
func TestSandboxInitBeforeBackend(t *testing.T) {
	requireSandboxRegression(t)
	assertSandboxListRefused(t, initSandboxItems, initSandboxError, initSandboxApplied)
}

// A nil receiver and captured method value cannot bypass the process sandbox.
func TestSandboxNilMethodValue(t *testing.T) {
	requireSandboxRegression(t)
	var value any
	store, _ := value.(*SecurityStore)
	list := store.List
	items, err := list()
	assertSandboxListRefused(t, items, err, keychaingate.Applied())
}
