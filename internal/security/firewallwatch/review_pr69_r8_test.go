package firewallwatch

// Regression witnesses from the independent PR69 review r8 (Codex,
// review-pr69-r8.md), kept as written by the reviewer.

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// A newline-terminated, syntactically valid JSON record with an invalid
// field type is semantic corruption, whether final or followed by a valid
// record. Controls: the unmodified record, and genuinely malformed JSON at
// EOF (the allowed torn tail). Every reader must preserve bytes.
func TestR8TypedFinalCorruption(t *testing.T) {
	for _, kind := range []string{"valid", "syntax", "entry-type", "time-value", "heartbeat-type"} {
		for _, later := range []bool{false, true} {
			if kind == "syntax" && later {
				continue
			}
			t.Run(fmt.Sprintf("%s/later=%t", kind, later), func(t *testing.T) {
				s, c := journalStore(t)
				b := time.Now().Add(-time.Minute).Round(0)
				if e := s.Save(b); e != nil {
					t.Fatal(e)
				}
				observeFlush(t, s, newKey(1), b.Add(time.Second))
				observeFlush(t, s, newKey(2), b.Add(2*time.Second))
				if e := s.Checkpoint(b.Add(3 * time.Second)); e != nil {
					t.Fatal(e)
				}
				rs := readJournal(t, s.journalPath())
				var target map[string]any
				raw, e := json.Marshal(rs[1])
				if e != nil {
					t.Fatal(e)
				}
				if kind == "heartbeat-type" {
					raw, e = json.Marshal(rs[2])
					if e != nil {
						t.Fatal(e)
					}
				}
				if e = json.Unmarshal(raw, &target); e != nil {
					t.Fatal(e)
				}
				target["seq"] = rs[1].Seq
				switch kind {
				case "entry-type":
					for _, entry := range target["entries"].(map[string]any) {
						entry.(map[string]any)["count"] = "bad"
					}
				case "time-value":
					target["last_event"] = "not-a-time"
				case "heartbeat-type":
					target["heartbeat"].(map[string]any)["backend_healthy"] = "bad"
				}
				raw, e = json.Marshal(target)
				if e != nil {
					t.Fatal(e)
				}
				if !json.Valid(raw) {
					t.Fatal("semantic fixture is not valid JSON")
				}
				if kind == "syntax" {
					raw = []byte("garbage")
				}
				prefix, _ := json.Marshal(rs[0])
				out := append(prefix, '\n')
				out = append(out, raw...)
				out = append(out, '\n')
				if later {
					next := rs[2]
					next.Seq = rs[1].Seq + 1
					line, _ := json.Marshal(next)
					out = append(out, line...)
					out = append(out, '\n')
				}
				if e = os.WriteFile(s.journalPath(), out, 0600); e != nil {
					t.Fatal(e)
				}
				before := dirHashes(t, c.StateDir)
				r, e := OpenStore(c)
				if !reflect.DeepEqual(before, dirHashes(t, c.StateDir)) {
					t.Fatal("reader changed bytes")
				}
				bad := kind != "valid" && kind != "syntax"
				if bad {
					if e == nil {
						t.Errorf("valid-JSON semantic corruption accepted as torn: events=%v torn=%d", eventApps(r.State.Events), r.State.Health.JournalTornTail)
						if !later {
							if se := r.Save(b.Add(4 * time.Second)); se != nil {
								t.Fatal("startup snapshot", se)
							}
							if _, se := os.Stat(r.journalPath()); !os.IsNotExist(se) {
								t.Fatal("startup journal cleanup", se)
							}
							t.Logf("startup snapshot erased corrupt journal; events=%v", eventApps(reopen(t, c).State.Events))
						}
					} else if !strings.Contains(e.Error(), "corrupt state journal") {
						t.Fatal(e)
					}
				} else {
					if e != nil {
						t.Fatal("positive control", e)
					}
					want := 2
					if kind == "syntax" {
						want = 1
					}
					if len(r.State.Events) != want {
						t.Fatal("positive control retained events", len(r.State.Events), want)
					}
				}
			})
		}
	}
}

// Reusing the exact historical start timestamp on a new run must still track
// the new live span across a snapshot, stall, and source end. Distinct-time
// runs and both small coverage caps are positive controls. Compare exact
// coverage and digest semantics; no real clock or collector is changed.
func TestR8EqualStartRestart(t *testing.T) {
	for _, cap := range []int{1, 2, 5} {
		for _, equal := range []bool{false, true} {
			t.Run(fmt.Sprintf("cap=%d/equal=%t", cap, equal), func(t *testing.T) {
				s, c := journalStore(t)
				c.MaxEntries = cap
				s.Config = c
				b := time.Now().Add(-time.Hour).Round(0)
				s.BeginCoverage(b)
				s.BeginSourceCoverage(SourceNetfilter, b)
				s.EndCoverage(b.Add(10 * time.Second))
				s.Coverage(SourceNetfilter).EndCoverage(b.Add(10 * time.Second))
				if e := s.Save(b.Add(10 * time.Second)); e != nil {
					t.Fatal(e)
				}
				s = reopen(t, c)
				start := b
				if !equal {
					start = b.Add(time.Minute)
				}
				if e := s.Save(start); e != nil {
					t.Fatal(e)
				}
				s.BeginCoverage(start)
				s.BeginSourceCoverage(SourceNetfilter, start)
				for step := 1; step <= 6; step++ {
					at := start.Add(time.Duration(step) * time.Second)
					for _, src := range []string{"", SourceNetfilter} {
						sc := s.Coverage(src)
						if step == 3 {
							sc.StallCoverage(at.Add(-time.Millisecond))
							sc.ResumeCoverage(at)
						}
						if step == 5 {
							sc.EndCoverage(at)
						}
					}
					var e error
					if step == 2 {
						e = s.Save(at)
					} else {
						e = s.Checkpoint(at)
					}
					if e != nil {
						t.Fatal(e)
					}
					before := dirHashes(t, c.StateDir)
					r := reopen(t, c)
					if !reflect.DeepEqual(before, dirHashes(t, c.StateDir)) {
						t.Fatal("reader changed bytes")
					}
					a, _ := json.Marshal(s.State.Coverage)
					z, _ := json.Marshal(r.State.Coverage)
					if string(a) != string(z) {
						t.Fatalf("step=%d runtime=%s replay=%s", step, a, z)
					}
					wa, wz := s.Split(start, at).Window, r.Split(start, at).Window
					if wa.Truncated != wz.Truncated || !reflect.DeepEqual(wa.CoverageGaps, wz.CoverageGaps) {
						t.Fatal("window mismatch")
					}
				}
			})
		}
	}
}
