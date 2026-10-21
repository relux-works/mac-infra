package firewallwatch

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Split puts each in-window event in at most one bucket with precedence
// real_deny > known_fp > needs_review. A non-nettop deny verdict (deny,
// denied, block, blocked, drop in any case) is real_deny whatever its label;
// a nettop row is never real_deny, and a verdict that merely contains a deny
// word is not one. Only decide rows enter known_fp or needs_review, and the three
// known-FP causes match only their exact source, verdict, reason, remote class
// and app. The reason is read from a string, a decoded map or a struct alike.
// The window counts only events at or after since.
func TestSplitBuckets(t *testing.T) {
	now := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	since := now.Add(-time.Hour)
	knnStruct := struct {
		Kind string `json:"kind"`
	}{Kind: "knn"}
	knnMap := map[string]any{"kind": "knn", "neighbours": []any{}}
	ev := func(min int, source, app, verdict, remote, label string, reason any) Event {
		return Event{TS: now.Add(time.Duration(min) * time.Minute), Source: source, App: app, Verdict: verdict, RemoteClass: remote, Label: label, Reason: reason}
	}
	s := &Store{State: State{Events: []Event{
		ev(-90, "alf", "old", "deny", "unknown", "decide", "hard_non_allow"),  // before since: excluded
		ev(-50, "alf", "a1", "deny", "unknown", "noise", "policy_apple_lan"),  // real_deny despite noise
		ev(-49, "alf", "a2", "block", "unknown", "decide", "hard_deny_spike"), // real_deny wins over known_fp
		ev(-48, "nettop", "Safari", "observed", "internet-raw-ip", "decide", "policy_raw_ip"),
		ev(-47, "nettop", "Safari", "observed", "internet-raw-ip", "digest", "policy_raw_ip"), // not decide: none
		ev(-46, "alf", "a3", "unknown", "unknown", "decide", "hard_non_allow"),
		ev(-45, "alf", "a4", "allow", "unknown", "decide", knnMap),
		ev(-44, "nettop", "/usr/bin/ssh", "observed", "loopback", "decide", knnStruct),
		ev(-43, "nettop", "limactl", "observed", "loopback", "decide", knnMap),
		ev(-42, "nettop", "curl", "observed", "loopback", "decide", knnMap),               // not ssh/limactl: review
		ev(-41, "nettop", "ssh", "observed", "internet", "decide", knnMap),                // not loopback: review
		ev(-40, "nettop", "ssh", "observed", "loopback", "decide", "policy_unusual_port"), // not knn: review
		ev(-39, "nettop", "x", "observed", "lan", "noise", "policy_apple_lan"),            // noise: none
		ev(-38, "alf", "a5", "DENIED", "unknown", "digest", "test"),                       // real_deny, case-folded
		ev(-37, "alf", "a6", "Blocked", "unknown", "", nil),                               // real_deny, empty label
		ev(-36, "alf", "a7", "drop", "unknown", "decide", "policy_raw_ip"),                // real_deny over known_fp
		ev(-35, "nettop", "n1", "deny", "internet", "decide", "policy_unusual_port"),      // nettop: review, not deny
		ev(-34, "alf", "a8", "verdict_code:2", "unknown", "decide", "hard_non_allow"),     // not a deny word: review
		ev(-33, "alf", "a9", "undeny", "unknown", "noise", "test"),                        // substring only: none
	}}}
	split := s.Split(since)
	var denied []string
	for _, row := range split.RealDeny {
		denied = append(denied, row.App)
	}
	if strings.Join(denied, ",") != "a1,a2,a5,a6,a7" {
		t.Fatalf("real_deny: %+v", split.RealDeny)
	}
	want := map[string]int{KnownFPNettopRawIP: 1, KnownFPALFUnknownOrAllow: 2, KnownFPLoopbackSSHKNN: 2}
	for group, count := range want {
		if g := split.KnownFP[group]; g.Count != count || len(g.Rows) != count {
			t.Errorf("%s: %+v, want %d", group, g, count)
		}
	}
	if len(split.NeedsReview) != 5 {
		t.Fatalf("needs_review: %+v", split.NeedsReview)
	}
	if split.Window.EventsInWindow != 18 || !split.Window.FirstTS.Equal(now.Add(-50*time.Minute)) || !split.Window.LastTS.Equal(now.Add(-33*time.Minute)) || split.Window.Truncated {
		t.Fatalf("window: %+v", split.Window)
	}
}

// truncated is set when the oldest retained event is newer than since (the
// retention cap or a stopped watcher hid the start) and for an empty store;
// it is clear when an older event proves the window start was retained.
// Empty buckets are JSON arrays, not null.
func TestSplitWindowTruncation(t *testing.T) {
	now := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	s := &Store{State: State{Events: []Event{{TS: now.Add(-10 * time.Minute), Source: "nettop", Label: "noise"}}}}
	if !s.Split(now.Add(-time.Hour)).Window.Truncated {
		t.Fatal("cap-cut window not marked truncated")
	}
	if s.Split(now.Add(-5 * time.Minute)).Window.Truncated {
		t.Fatal("covered window marked truncated")
	}
	empty := (&Store{}).Split(now.Add(-time.Hour))
	if !empty.Window.Truncated || empty.Window.FirstTS != nil {
		t.Fatalf("empty store window: %+v", empty.Window)
	}
	data, err := json.Marshal(empty)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	_ = json.Unmarshal(data, &decoded)
	for _, key := range []string{"real_deny", "needs_review"} {
		if _, ok := decoded[key].([]any); !ok {
			t.Fatalf("%s is not an array: %s", key, data)
		}
	}
	fp := decoded["known_fp"].(map[string]any)
	for _, group := range []string{KnownFPNettopRawIP, KnownFPALFUnknownOrAllow, KnownFPLoopbackSSHKNN} {
		if rows, ok := fp[group].(map[string]any)["rows"].([]any); !ok || rows == nil {
			t.Fatalf("known_fp %s rows not an array: %s", group, data)
		}
	}
	if decoded["health"].(map[string]any)["mode"] != "shadow" {
		t.Fatalf("health mode missing: %s", data)
	}
}
