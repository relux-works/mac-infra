package firewallwatch

// Regression witnesses from the independent PR69 review r7 (Codex,
// review-pr69-r7.md), kept as written by the reviewer.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// A structurally invalid complete non-final record is corruption, even if a
// later record overwrites the bad field. Positive controls are identical
// valid records. The invalid-event control remains visible (changing Mode
// also changes its removal identity) and is refused. No file may change.
func TestR7OverwrittenCorruption(t *testing.T) {
	for _, field := range []string{"entry", "signer", "heartbeat", "event"} {
		for _, bad := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/bad=%t", field, bad), func(t *testing.T) {
				s, c := journalStore(t)
				c.MaxEntries = 1
				s.Config = c
				b := time.Now().Add(-time.Minute).Round(0)
				if e := s.Save(b); e != nil {
					t.Fatal(e)
				}
				observeFlush(t, s, newKey(1), b.Add(time.Second))
				if field == "signer" {
					s.State.Signers["fixture"] = SignerEntry{Value: "valid", LastSeen: b}
					s.signerChanged("fixture")
					s.delta.urgent = true
					if e := s.Flush(b.Add(2*time.Second), false, false); e != nil {
						t.Fatal(e)
					}
					s.State.Signers["fixture"] = SignerEntry{Value: "new", LastSeen: b.Add(time.Second)}
					s.signerChanged("fixture")
					s.delta.urgent = true
				}
				if field == "heartbeat" {
					if e := s.Checkpoint(b.Add(2 * time.Second)); e != nil {
						t.Fatal(e)
					}
				}
				if field == "entry" {
					s.Observe(newKey(1), b.Add(2*time.Second), ruleClassify)
				}
				if field == "event" {
					observeFlush(t, s, newKey(2), b.Add(2*time.Second))
				}
				if e := s.Checkpoint(b.Add(3 * time.Second)); e != nil {
					t.Fatal(e)
				}
				records := readJournal(t, s.journalPath())
				if len(records) < 2 {
					t.Fatal("fixture records")
				}
				var target int
				switch field {
				case "entry":
					records[0].Entries[key(cleanItem(newKey(1)))].Count = map[bool]uint64{false: 1, true: 0}[bad]
				case "signer":
					target = 1
					v := records[target].Signers["fixture"]
					if bad {
						v.Value = strings.Repeat("x", 1025)
					}
					records[target].Signers["fixture"] = v
				case "heartbeat":
					target = 1
					if bad {
						records[target].Heartbeat.Health.LineQueueHighWater.ALF = 65
					}
				case "event":
					if bad {
						records[0].Events[0].Mode = "invalid"
					}
				}
				// Establish that the same record violates the candidate's own per-item
				// validator, independently of the expectation about replay.
				if e := s.validateRecord(records[target]); (e != nil) != bad {
					t.Fatalf("record validator: %v", e)
				}
				var raw []byte
				for _, r := range records {
					line, e := json.Marshal(r)
					if e != nil {
						t.Fatal(e)
					}
					raw = append(raw, append(line, '\n')...)
				}
				if e := os.WriteFile(s.journalPath(), raw, 0600); e != nil {
					t.Fatal(e)
				}
				before := dirHashes(t, c.StateDir)
				r, e := OpenStore(c)
				if fmt.Sprint(before) != fmt.Sprint(dirHashes(t, c.StateDir)) {
					t.Fatal("reader changed bytes")
				}
				if bad && e == nil {
					t.Errorf("invalid non-final %s record silently accepted; retained events=%d", field, len(r.State.Events))
				}
				if !bad && e != nil {
					t.Fatal("valid control refused", e)
				}
			})
		}
	}
}

// A one-character count corruption is refused when visible at EOF and must
// also be refused when a subsequent legitimate refresh replaces that entry.
// Valid one-record and two-record journals are independent positive controls.
func TestR7InvalidEntryOverwritten(t *testing.T) {
	for _, bad := range []bool{false, true} {
		for _, later := range []bool{false, true} {
			t.Run(fmt.Sprintf("bad=%t/later=%t", bad, later), func(t *testing.T) {
				s, c := journalStore(t)
				b := time.Now().Add(-time.Minute).Round(0)
				if e := s.Save(b); e != nil {
					t.Fatal(e)
				}
				observeFlush(t, s, newKey(1), b.Add(time.Second))
				s.Observe(newKey(1), b.Add(2*time.Second), ruleClassify)
				if e := s.Checkpoint(b.Add(2 * time.Second)); e != nil {
					t.Fatal(e)
				}
				records := readJournal(t, s.journalPath())
				if len(records) != 2 {
					t.Fatal("fixture records")
				}
				if bad {
					records[0].Entries[key(cleanItem(newKey(1)))].Count = 0
				}
				if e := s.validateRecord(records[0]); (e != nil) != bad {
					t.Fatal("per-item control", e)
				}
				var raw []byte
				for i, r := range records {
					if i == 1 && !later {
						break
					}
					line, e := json.Marshal(r)
					if e != nil {
						t.Fatal(e)
					}
					raw = append(raw, append(line, '\n')...)
				}
				if e := os.WriteFile(s.journalPath(), raw, 0600); e != nil {
					t.Fatal(e)
				}
				before := dirHashes(t, c.StateDir)
				r, e := OpenStore(c)
				if fmt.Sprint(before) != fmt.Sprint(dirHashes(t, c.StateDir)) {
					t.Fatal("reader changed bytes")
				}
				if bad {
					if e == nil {
						t.Errorf("invalid complete record accepted after later refresh; restored count=%d", r.State.Entries[key(cleanItem(newKey(1)))].Count)
					}
					return
				}
				if e != nil {
					t.Fatal("valid control refused", e)
				}
				want := uint64(1)
				if later {
					want = 2
				}
				if r.State.Entries[key(cleanItem(newKey(1)))].Count != want {
					t.Fatal("valid refresh lost")
				}
			})
		}
	}
}
