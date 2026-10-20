package main

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/netnone"
)

// Usage errors never construct an engine or invoke tools; help/version are successful controls.
func TestCommandValidation(t *testing.T) {
	for _, row := range []struct {
		args []string
		code int
	}{
		{nil, 2}, {[]string{"help"}, 0}, {[]string{"version"}, 0}, {[]string{"unknown"}, 2},
		{[]string{"prep"}, 2}, {[]string{"run", "--repo", "/repo", "--task", "test"}, 2},
		{[]string{"selftest", "--max-load", "0"}, 2}, {[]string{"selftest", "--max-load", "NaN"}, 2}, {[]string{"selftest", "--max-load", "+Inf"}, 2},
		{[]string{"selftest", "--cpus", "0"}, 2}, {[]string{"selftest", "--memory", "-1"}, 2}, {[]string{"selftest", "--disk", "1.5"}, 2},
		{[]string{"run", "--db-image", "x"}, 2}, {[]string{"status", "--repo", "/repo"}, 2}, {[]string{"stop", "extra"}, 2}, {[]string{"prep", "--help"}, 0},
	} {
		var out, err bytes.Buffer
		code := runWith(context.Background(), row.args, &out, &err, func(io.Writer, io.Writer) *netnone.Engine { t.Fatal("usage invoked engine"); return nil })
		if code != row.code {
			t.Fatalf("%v exit=%d want=%d %s", row.args, code, row.code, &err)
		}
	}
}

type cliFake struct{ calls []netnone.Command }

func (f *cliFake) Run(_ context.Context, c netnone.Command) (netnone.Result, error) {
	f.calls = append(f.calls, c)
	return netnone.Result{Stdout: []byte(`{"status":"Running"}`)}, nil
}

// CLI flags reach the fake-backed engine and its load refusal preserves exit 3 without any tool command.
func TestCLIRefusalAndStatus(t *testing.T) {
	for _, action := range []string{"selftest", "status"} {
		var out, err bytes.Buffer
		f := &cliFake{}
		args := []string{action}
		if action == "selftest" {
			args = append(args, "--max-load", "2", "--cpus", "6", "--memory", "12", "--disk", "80")
		}
		root := t.TempDir()
		code := runWith(context.Background(), args, &out, &err, func(out, errOut io.Writer) *netnone.Engine {
			e := netnone.New(f, out, errOut)
			e.Home = func() (string, error) { return root, nil }
			e.StateDir = func(string) string { return filepath.Join(root, "state") }
			e.Load = func(context.Context) ([3]float64, error) { return [3]float64{1, 3, 2}, nil }
			return e
		})
		if action == "selftest" {
			if code != 3 || len(f.calls) != 0 || !strings.Contains(err.String(), "above --max-load 2") {
				t.Fatalf("refusal %d calls=%d %s", code, len(f.calls), &err)
			}
		} else if code != 0 || len(f.calls) != 1 || !strings.Contains(out.String(), `"Profile":"running"`) {
			t.Fatalf("status %d %s %s", code, &out, &err)
		}
	}
}
