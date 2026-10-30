package firewallwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Both review cosine witnesses reject unsupported noise; nearby admitted noise and ties remain valid.
func TestReviewVoting(t *testing.T) {
	for _, tc := range []struct {
		name   string
		scores []float64
		labels []string
		want   string
	}{
		{"negative", []float64{.6, -.8, -.9}, []string{"decide", "decide", "digest"}, "decide"},
		{"weak", []float64{.9, .49, .49}, []string{"decide", "noise", "noise"}, "decide"},
		{"noise_control", []float64{.9, .51, .51}, []string{"decide", "noise", "noise"}, "noise"},
		{"tie_control", []float64{.6, .6, .1}, []string{"digest", "decide", "noise"}, "decide"},
		{"novel_control", []float64{.49, .2, -.9}, []string{"noise", "digest", "decide"}, "decide"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl, _ := fakeClassifier(t, embeddingHandler, 1, .5)
			cl.cfg.K = 3
			cl.pool = nil
			cl.vectors = nil
			for i, s := range tc.scores {
				cl.pool = append(cl.pool, Item{ID: tc.labels[i], Label: tc.labels[i]})
				cl.vectors = append(cl.vectors, []float64{s, math.Sqrt(1 - s*s)})
			}
			d := cl.Classify(context.Background(), unmatched("near"))
			if d.Label != tc.want {
				t.Fatalf("got %+v want %s", d, tc.want)
			}
		})
	}
}

// Repeats re-evaluate current upload and signer facts, emitting each newly triggered decide rule once.
func TestReviewRepeatEscalation(t *testing.T) {
	for _, kind := range []string{"bytes", "signer"} {
		t.Run(kind, func(t *testing.T) {
			s, e := OpenStore(testConfig(t))
			if e != nil {
				t.Fatal(e)
			}
			now := time.Now()
			it := Item{App: "/Applications/Tool.app", Source: "nettop", Kind: "outbound", Signer: "Apple", Verdict: "observed", Remote: "lan", Count: 1}
			if kind == "signer" {
				it.Source = "alf"
				it.Kind = "unknown"
				it.Verdict = "allow"
			}
			if got := s.Observe(it, now, ruleClassify); len(got) != 1 {
				t.Fatal(got)
			}
			if got := s.Observe(it, now.Add(time.Second), ruleClassify); len(got) != 0 {
				t.Fatal("ordinary repeat", got)
			}
			reason := "policy_upload_spike"
			it.MBOut = 1000
			if kind == "signer" {
				it.MBOut = 0
				it.Signer = "ad-hoc"
				reason = "hard_unsigned_inbound"
			}
			got := s.Observe(it, now.Add(2*time.Second), ruleClassify)
			if len(got) != 1 || got[0].Label != "decide" || got[0].Reason != reason {
				t.Fatalf("missing escalation: %+v", got)
			}
			if got := s.Observe(it, now.Add(3*time.Second), ruleClassify); len(got) != 0 {
				t.Fatal("duplicate escalation", got)
			}
			if e = s.Save(now.Add(3 * time.Second)); e != nil {
				t.Fatal(e)
			}
			s, e = OpenStore(s.Config)
			if e != nil {
				t.Fatal(e)
			}
			if got := s.Observe(it, now.Add(4*time.Second), ruleClassify); len(got) != 0 {
				t.Fatal("escalation repeated after reload", got)
			}
		})
	}
}

// IPv6 filename and punctuation suffixes are redacted; adjacent non-address text stays intact.
func TestReviewIPv6Suffix(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Tool-fd7a:115c:a1e0:abcd::67.app", "Tool-[ip].app"},
		{"fd7a:115c:a1e0:abcd::67.", "[ip]."},
		{"x(fd7a:115c:a1e0:abcd::67),", "x([ip]),"},
		{"face.app", "face.app"}, {"a:b:c.app", "a:b:c.app"}, {"version-1.2.3.app", "version-1.2.3.app"},
	} {
		if got := Sanitize(tc.in); got != tc.want {
			t.Errorf("%q => %q want %q", tc.in, got, tc.want)
		}
	}
}

// Semantically corrupt and oversized state is refused without changing evidence; a valid state reloads.
func TestReviewCorruptState(t *testing.T) {
	for _, raw := range []string{`{"entries":{"bad":null}}`, `null`, `{"entries":null,"signers":{}}`, `{"entries":{},"signers":null}`, `{"entries":{},"signers":{"bad":null}}`, `{"entries":{"bad":{"count":0}},"signers":{}}`, `{"entries":{},"signers":{},"events":[null]}`, `{"entries":{},"signers":{}}` + strings.Repeat(" ", 4097)} {
		t.Run(strings.TrimSpace(raw)[:min(16, len(strings.TrimSpace(raw)))], func(t *testing.T) {
			c := testConfig(t)
			b, _ := json.Marshal(c)
			var fields map[string]any
			_ = json.Unmarshal(b, &fields)
			fields["max_state_bytes"] = 4096
			b, _ = json.Marshal(fields)
			_ = json.Unmarshal(b, &c)
			_ = os.Mkdir(c.StateDir, 0700)
			p := filepath.Join(c.StateDir, "state.json")
			_ = os.WriteFile(p, []byte(raw), 0600)
			defer func() {
				got, _ := os.ReadFile(p)
				if string(got) != raw {
					t.Error("corruption evidence overwritten")
				}
				if v := recover(); v != nil {
					t.Errorf("panic instead of corruption error: %v", v)
				}
			}()
			if _, e := OpenStore(c); e == nil || !strings.Contains(e.Error(), "corrupt") {
				t.Errorf("want corruption error, got %v", e)
			}
		})
	}
	c := testConfig(t)
	s, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Save(time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e = OpenStore(c); e != nil {
		t.Fatal("valid control", e)
	}
}

// Zero and negative thresholds are invalid; positive finite thresholds through one are admitted.
func TestReviewThreshold(t *testing.T) {
	for _, v := range []float64{-1, 0, math.NaN(), .01, 1} {
		c := testConfig(t)
		c.NoveltySimilarity = &v
		e := c.Validate()
		want := v > 0 && v <= 1
		if (e == nil) != want {
			t.Errorf("threshold %g: %v", v, e)
		}
	}
}

// Unknown signer on ALF acceptance fails conservatively, while nettop and signed ALF do not trigger this rule.
func TestReviewUnverifiedInbound(t *testing.T) {
	it := Item{App: "/Applications/Tool.app", Source: "alf", Kind: "unknown", Signer: "unknown", Verdict: "allow", Remote: "unknown"}
	if d, ok := Rules(it); !ok || d.Label != "decide" || d.Reason != "hard_unverified_inbound" {
		t.Errorf("unverified: %+v", d)
	}
	for _, kind := range []string{"nettop", "signed"} {
		control := it
		if kind == "nettop" {
			control.Source = "nettop"
			control.Verdict = "observed"
		} else {
			control.Signer = "Apple"
		}
		if d, _ := Rules(control); d.Reason == "hard_unverified_inbound" {
			t.Error("control", d)
		}
	}
}

// A new key is durable at once through the journal, without rewriting
// state.json or a day file; silent repeats write nothing and their state
// follows in one heartbeat per interval. Day files are written only by a
// snapshot, which leaves an unchanged day alone, and a forced flush takes a
// snapshot (BUG-261029-kpyw8s).
func TestReviewWriteAmplification(t *testing.T) {
	c := testConfig(t)
	s, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	writes := map[string]int{}
	s.atomicWrite = func(path string, b []byte) error { writes[filepath.Base(path)]++; return atomicWrite(path, b) }
	now := time.Now()
	it := Item{App: "app", Source: "nettop", Verdict: "observed", Remote: "lan"}
	observe := func(at time.Time) {
		t.Helper()
		emitted := len(s.Observe(it, at, ruleClassify)) > 0
		if e := s.Flush(at, emitted, false); e != nil {
			t.Fatal(e)
		}
	}
	types := func() map[string]int {
		t.Helper()
		got := map[string]int{}
		for _, r := range readJournal(t, s.journalPath()) {
			if len(r.Events) > 0 {
				got["events"]++
			}
			if r.Heartbeat != nil {
				got["heartbeat"]++
			}
		}
		return got
	}
	observe(now)
	day := "events-" + now.UTC().Format("2006-01-02") + ".jsonl"
	if writes["state.json"] != 0 || writes[day] != 0 || types()["events"] != 1 || writes["new-events.flag"] != 1 {
		t.Fatal("new key not journaled at once", writes, types())
	}
	clear(writes)
	for i := 1; i <= 100; i++ {
		observe(now.Add(time.Duration(i) * time.Millisecond))
	}
	if len(writes) != 0 || types()["events"] != 1 {
		t.Fatal("repeat write amplification", writes, types())
	}
	beats := types()["heartbeat"] // a fresh store's first flush also writes one
	if e = s.Flush(now.Add(11*time.Second), false, false); e != nil {
		t.Fatal(e)
	}
	if e = s.Flush(now.Add(12*time.Second), false, false); e != nil {
		t.Fatal(e)
	}
	if len(writes) != 0 || types()["heartbeat"] != beats+1 {
		t.Fatal("interval writes", writes, types())
	}
	it.App = "another"
	observe(now.Add(13 * time.Second))
	if writes["state.json"] != 0 || types()["events"] != 2 {
		t.Fatal("new key delayed", writes, types())
	}
	// A snapshot writes the day; a later snapshot after changes on a second
	// day must not rewrite the first day's projection.
	if e = s.Flush(now.Add(14*time.Second), false, true); e != nil {
		t.Fatal(e)
	}
	if writes["state.json"] != 1 || writes[day] != 1 || len(readJournal(t, s.journalPath())) != 0 {
		t.Fatal("forced snapshot", writes)
	}
	clear(writes)
	it.App = "next day"
	observe(now.Add(24 * time.Hour))
	if e = s.Flush(now.Add(24*time.Hour+time.Second), false, true); e != nil {
		t.Fatal(e)
	}
	next := "events-" + now.Add(24*time.Hour).UTC().Format("2006-01-02") + ".jsonl"
	if writes[day] != 0 || writes[next] != 1 {
		t.Fatal("unchanged day rewritten", writes)
	}
}

// Same-path replacement invalidates signed metadata; failure expiry retries without refreshing the TTL on hits.
func TestReviewSignerIdentityAndTTL(t *testing.T) {
	for _, kind := range []string{"replacement", "failure"} {
		t.Run(kind, func(t *testing.T) {
			c := testConfig(t)
			s, e := OpenStore(c)
			if e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(t.TempDir(), "tool")
			if e = os.WriteFile(path, []byte("signed"), 0600); e != nil {
				t.Fatal(e)
			}
			now := time.Now()
			s.clock = func() time.Time { return now }
			calls := 0
			s.inspectSigner = signerOnly(func(_ context.Context, got string) (string, error) {
				calls++
				if got != path {
					t.Fatal(got)
				}
				if calls == 1 {
					if kind == "failure" {
						return "", fmt.Errorf("inspection failed")
					}
					return "Developer ID: trusted", nil
				}
				return "ad-hoc", nil
			})
			first := s.signer(context.Background(), path)
			if kind == "failure" {
				if first != "unknown" {
					t.Fatal(first)
				}
			} else if first != "Developer ID: trusted" {
				t.Fatal(first)
			}
			now = now.Add(500 * time.Millisecond)
			if got := s.signer(context.Background(), path); got != first || calls != 1 {
				t.Fatal("cache control", got, calls)
			}
			if kind == "replacement" {
				replacement := path + ".new"
				_ = os.WriteFile(replacement, []byte("unsigned"), 0600)
				if e = os.Rename(replacement, path); e != nil {
					t.Fatal(e)
				}
			} else {
				now = now.Add(time.Second)
			}
			if got := s.signer(context.Background(), path); got != "ad-hoc" || calls != 2 {
				t.Fatal("stale signer returned", got, calls)
			}
		})
	}
}

// Operational paths reach inspection unchanged, while IP literals are redacted in events, state and rendered features.
func TestReviewInspectionPathPrivacy(t *testing.T) {
	for _, name := range []string{"Tool-192.168.1.5.app", "Tool.app"} {
		t.Run(name, func(t *testing.T) {
			c := testConfig(t)
			s, e := OpenStore(c)
			if e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(t.TempDir(), name)
			if e = os.Mkdir(path, 0700); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(path, "code"), []byte("original code"), 0600); e != nil {
				t.Fatal(e)
			}
			line, _ := json.Marshal(map[string]string{"category": "fw", "eventMessage": "KNOWN APP FLOW: " + path + ", return known verdict: 1"})
			it := s.State.Parser.Parse(line)
			if it == nil {
				t.Fatal("parse")
			}
			if it.InspectionPath != path {
				t.Fatalf("operational path changed: %q", it.InspectionPath)
			}
			calls := 0
			currentSigner := "ad-hoc"
			s.inspectSigner = signerOnly(func(_ context.Context, got string) (string, error) {
				calls++
				if got != path {
					t.Fatalf("codesign received %q want %q", got, path)
				}
				return currentSigner, nil
			})
			it.Signer = s.signer(context.Background(), it.InspectionPath)
			events := s.Observe(*it, time.Now(), ruleClassify)
			if calls != 1 || len(events) != 1 {
				t.Fatal(calls, events)
			}
			if e = s.Save(time.Now()); e != nil {
				t.Fatal(e)
			}
			raw, e := os.ReadFile(filepath.Join(c.StateDir, "state.json"))
			if e != nil {
				t.Fatal(e)
			}
			for _, value := range []string{string(raw), Render(*it)} {
				if strings.Contains(value, "192.168.1.5") {
					t.Fatal("raw path persisted/rendered", value)
				}
			}
			if strings.Contains(name, "192.") && !strings.Contains(string(raw), "[ip]") {
				t.Fatal("missing redaction")
			}
			if name == "Tool.app" && events[0].App != path {
				t.Fatal("plain control changed", events)
			}
			if e = os.WriteFile(filepath.Join(path, "code"), []byte("changed bundle code"), 0600); e != nil {
				t.Fatal(e)
			}
			currentSigner = "unsigned"
			if got := s.signer(context.Background(), path); got != "unsigned" || calls != 2 {
				t.Fatal("stale bundle signer", got, calls)
			}
		})
	}
}

// Child command constructors preserve literal argv, clear injected environment, and pass only the verified fd to llama-server.
func TestReviewChildCommands(t *testing.T) {
	t.Setenv("DYLD_INSERT_LIBRARIES", "untrusted")
	t.Setenv("LLAMA_ARG_HOST", "0.0.0.0")
	ctx := context.Background()
	path := "/Applications/Tool 192.168.1.5.app"
	for _, tc := range []struct {
		cmd  *exec.Cmd
		argv []string
	}{
		{codesignCommand(ctx, path), []string{"/usr/bin/codesign", "-dv", "--verbose=2", path}},
		{collectorCommand(ctx, "log"), []string{"/usr/bin/log", "stream", "--style", "ndjson", "--info", "--predicate", `subsystem == "com.apple.ALF.ApplicationFirewall"`}},
		{collectorCommand(ctx, "nettop"), []string{"/usr/bin/nettop", "-L", "1", "-n", "-x", "-J", "bytes_out"}},
	} {
		if !reflect.DeepEqual(tc.cmd.Args, tc.argv) || !reflect.DeepEqual(tc.cmd.Env, []string{"PATH=/usr/bin:/bin", "LANG=C"}) {
			t.Fatalf("unsafe command: argv=%q env=%q", tc.cmd.Args, tc.cmd.Env)
		}
	}
	c := testConfig(t)
	f, e := os.Create(c.Model)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	cmd := backendCommand(ctx, c, f)
	want := []string{c.LlamaServer, "--offline", "--host", c.SocketPath(), "--embedding", "--pooling", "last", "-m", "/dev/fd/3"}
	if !reflect.DeepEqual(cmd.Args, want) || cmd.Env == nil || len(cmd.Env) != 0 || len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0] != f {
		t.Fatalf("unsafe backend: argv=%q env=%q fds=%v", cmd.Args, cmd.Env, cmd.ExtraFiles)
	}
}

// A competing writer is refused before loading even corrupt state, without executing any host collector.
func TestReviewRunLockBeforeLoad(t *testing.T) {
	c := testConfig(t)
	s, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	unlock, e := s.Lock()
	if e != nil {
		t.Fatal(e)
	}
	defer unlock()
	if e = os.WriteFile(filepath.Join(c.StateDir, "state.json"), []byte(`null`), 0600); e != nil {
		t.Fatal(e)
	}
	if e = Run(context.Background(), c, nil); e == nil || e.Error() != "watcher already running" {
		t.Fatalf("expected lock refusal before load, got %v", e)
	}
}
