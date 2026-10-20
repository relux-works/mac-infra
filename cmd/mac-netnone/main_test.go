package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

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
		{[]string{"selftest", "--arch", "x86"}, 2}, {[]string{"selftest", "--arch", ""}, 2},
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
	return netnone.Result{Stdout: []byte(`{"name":"netnone","status":"Running"}`)}, nil
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

type signalFake struct{ root string }

func (f signalFake) Run(ctx context.Context, c netnone.Command) (netnone.Result, error) {
	switch c.Args[0] {
	case "list":
		return netnone.Result{Stdout: []byte(`{"name":"netnone","status":"Stopped"}`)}, nil
	case "start":
		if err := os.WriteFile(filepath.Join(f.root, "ready"), []byte("ready"), 0600); err != nil {
			return netnone.Result{}, err
		}
		<-ctx.Done()
		return netnone.Result{}, ctx.Err()
	case "stop":
		if ctx.Err() != nil {
			return netnone.Result{}, ctx.Err()
		}
		return netnone.Result{}, os.WriteFile(filepath.Join(f.root, "stopped"), []byte("stopped"), 0600)
	}
	return netnone.Result{}, fmt.Errorf("unexpected command: %s %v", c.Name, c.Args)
}

// F4: real INT/TERM/HUP delivered to our own helper PID cancel fake startup and complete rollback before exit.
func TestTerminationSignals(t *testing.T) {
	if root := os.Getenv("NETNONE_SIGNAL_FIXTURE"); root != "" {
		ctx, cancel := terminationContext()
		defer cancel()
		e := netnone.New(signalFake{root}, io.Discard, io.Discard)
		e.Home = func() (string, error) { return root, nil }
		e.StateDir = func(string) string { return filepath.Join(root, "state") }
		e.Load = func(context.Context) ([3]float64, error) { return [3]float64{}, nil }
		o := netnone.DefaultOptions()
		o.Repo = root
		o.Task = "test"
		if code := e.Execute(ctx, "prep", o); code != 1 {
			t.Fatalf("signal exit=%d", code)
		}
		if _, err := os.Stat(filepath.Join(root, "stopped")); err != nil {
			t.Fatal("signal did not finish stop", err)
		}
		return
	}
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			root := t.TempDir()
			cmd := exec.Command(os.Args[0], "-test.run=^TestTerminationSignals$")
			cmd.Env = append(os.Environ(), "NETNONE_SIGNAL_FIXTURE="+root)
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			// cmd.Process.Pid is the sole process this test owns; never use pattern-based process control.
			t.Logf("signal helper pid=%d", cmd.Process.Pid)
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			defer func() { _ = cmd.Process.Kill() }()
			deadline := time.NewTimer(10 * time.Second)
			defer deadline.Stop()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
		ready:
			for {
				if _, err := os.Stat(filepath.Join(root, "ready")); err == nil {
					break ready
				}
				select {
				case err := <-done:
					t.Fatalf("helper stopped before signal: %v %s", err, &output)
				case <-deadline.C:
					t.Fatal("helper did not reach fake startup")
				case <-ticker.C:
				}
			}
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("signal bypassed cleanup: %v %s", err, &output)
				}
			case <-deadline.C:
				t.Fatal("signal cleanup timed out")
			}
			if _, err := os.Stat(filepath.Join(root, "stopped")); err != nil {
				t.Fatal("signal left fake VM running", err)
			}
		})
	}
}

type archCLIFake struct{ calls []netnone.Command }

func (f *archCLIFake) Run(_ context.Context, c netnone.Command) (netnone.Result, error) {
	f.calls = append(f.calls, c)
	switch c.Name + " " + c.Args[0] {
	case "colima list":
		return netnone.Result{Stdout: []byte(`{"name":"netnone","status":"Stopped"}`)}, nil
	case "colima start":
		return netnone.Result{ExitCode: 7}, nil
	case "colima stop":
		return netnone.Result{}, nil
	case "docker context":
		if c.Args[1] == "ls" {
			return netnone.Result{Stdout: []byte(`{"Name":"default","Current":true}`)}, nil
		}
		return netnone.Result{Stdout: []byte(`[{"Name":"default"}]`)}, nil
	}
	return netnone.Result{}, fmt.Errorf("unexpected fake call %s %v", c.Name, c.Args)
}

// CLI architecture flags reach Options on all lifecycle commands; omission selects arm64, and fake startup failure still stops.
func TestCLIArchitectureOptions(t *testing.T) {
	for _, action := range []string{"prep", "run", "selftest"} {
		for _, archFlag := range []string{"", "arm64", "amd64"} {
			t.Run(action+"/"+archFlag, func(t *testing.T) {
				root, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				state := filepath.Join(root, "state")
				if err := os.Mkdir(state, 0700); err != nil {
					t.Fatal(err)
				}
				arch := archFlag
				if arch == "" {
					arch = "arm64"
				}
				records := map[string]any{root + "\nbase\n" + arch: map[string]string{"repo": root, "toolchain_sha256": "base", "arch": arch, "image_id": "sha256:" + strings.Repeat("a", 64)}}
				data, err := json.Marshal(records)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(state, "prep-records.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
				args := []string{action}
				if action != "selftest" {
					args = append(args, "--repo", root, "--task", "test")
				}
				if action == "run" {
					args = append(args, "--out", root)
				}
				if archFlag != "" {
					args = append(args, "--arch", archFlag)
				}
				var out, errOut bytes.Buffer
				f := &archCLIFake{}
				code := runWith(context.Background(), args, &out, &errOut, func(out, errOut io.Writer) *netnone.Engine {
					e := netnone.New(f, out, errOut)
					e.Home = func() (string, error) { return root, nil }
					e.StateDir = func(string) string { return state }
					e.Load = func(context.Context) ([3]float64, error) { return [3]float64{}, nil }
					e.UserEnv = []string{}
					return e
				})
				if code != 1 {
					t.Fatalf("startup fixture exit=%d %s", code, &errOut)
				}
				rosetta := "--vz-rosetta=false"
				if arch == "amd64" {
					rosetta = "--vz-rosetta"
				}
				starts, stops := 0, 0
				for _, c := range f.calls {
					if c.Name != "colima" {
						continue
					}
					if c.Args[0] == "start" {
						starts++
						found := false
						for _, a := range c.Args {
							if a == rosetta {
								found = true
							}
						}
						if !found {
							t.Fatalf("CLI arch did not reach startup: %v", c.Args)
						}
					}
					if c.Args[0] == "stop" {
						stops++
					}
				}
				if starts != 1 || stops != 1 {
					t.Fatalf("startup/stop=%d/%d", starts, stops)
				}
			})
		}
	}
}
