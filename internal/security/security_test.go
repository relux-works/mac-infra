package security

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// The production runner refuses shell, sudo and mutation commands before
// execution; the bounded output sink refuses to retain more than its limit.
func TestRunnerClosedVocabularyAndOutputBound(t *testing.T) {
	for _, path := range []string{"/bin/sh", "/usr/bin/sudo", "/usr/bin/defaults"} {
		if _, err := (CommandRunner{}).Run(context.Background(), path, "write", "anything"); err == nil {
			t.Fatal(path)
		}
	}
	if !allowedCommand("/usr/bin/csrutil", []string{"status"}) {
		t.Fatal("valid read rejected")
	}
	b := limitedBuffer{max: 4}
	b.Write([]byte("abcdef"))
	if !b.exceeded || string(b.data) != "abcd" {
		t.Fatal(string(b.data), b.exceeded)
	}
}

// Operational failures keep timestamps and unknown exit status without leaking
// backend errors; successful controls retain exit 0 evidence.
func TestObserveEvidence(t *testing.T) {
	fn := func(ctx context.Context, r Runner) Check {
		_, err := r.Run(ctx, "/usr/bin/csrutil", "status")
		if err != nil {
			return unavailable("test", false, "unavailable")
		}
		return Check{Name: "test", Status: "ok"}
	}
	for _, err := range []error{nil, errors.New("secret-error")} {
		c := Observe(context.Background(), coreFakeRunner{err: err}, fn)
		if c.StartedAt.IsZero() || c.FinishedAt.Before(c.StartedAt) || len(c.Commands) != 1 {
			t.Fatal(c)
		}
		if err == nil && (*c.Commands[0].ExitCode != 0) {
			t.Fatal(c)
		}
		if err != nil && c.Commands[0].ExitCode != nil {
			t.Fatal(c)
		}
	}
}

func fixtureDir(t *testing.T) string {
	t.Helper()
	p, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return p
}
