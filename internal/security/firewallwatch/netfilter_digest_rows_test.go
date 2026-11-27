package firewallwatch

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func netfilterRowsEvent(at time.Time) Event {
	return Event{TS: at, Source: SourceNetfilter, App: "/app", Signer: "Developer", Kind: "outbound", RemoteClass: "internet", Bucket: "example.test", Counts: 100, Label: "decide", Reason: "policy_unusual_port", Mode: "shadow"}
}

// Retained rows count once, including inclusive endpoints; other sources and
// out-of-window rows do not contribute. Missing directions stay unknown.
func TestNetfilterRowsWindow(t *testing.T) {
	since := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	asOf := since.Add(time.Hour)
	first, last := netfilterRowsEvent(since), netfilterRowsEvent(asOf)
	middle := netfilterRowsEvent(since.Add(time.Minute))
	middle.Kind = ""
	unknown := middle
	unknown.Kind = "unknown"
	inbound := middle
	inbound.Kind = "inbound"
	before, after := first, last
	before.TS = since.Add(-time.Nanosecond)
	after.TS = asOf.Add(time.Nanosecond)
	alf, nettop := middle, middle
	alf.Source, nettop.Source = "alf", "nettop"
	events := []Event{last, middle, before, inbound, first, after, unknown, alf, nettop}
	got := buildNetfilterRows(events, since, asOf)
	if got.EventRows != 5 || got.OutboundEventRows != 2 || got.UnknownDirectionEventRows != 2 || got.FirstTS == nil || !got.FirstTS.Equal(since) || got.LastTS == nil || !got.LastTS.Equal(asOf) {
		t.Fatalf("retained window: %+v", got)
	}
	if len(got.PerApp) != 1 || got.PerApp[0].EventRows != 5 || got.PerApp[0].OutboundEventRows != 2 || got.PerApp[0].UnknownDirectionEventRows != 2 || got.PerApp[0].DistinctRetainedDestinations != 3 {
		t.Fatalf("per-app totals: %+v", got.PerApp)
	}
	if len(got.Destinations) != 3 || got.Destinations[0].Direction != "inbound" || got.Destinations[1].Direction != "outbound" || got.Destinations[2].Direction != "unknown" || got.Destinations[2].EventRows != 2 {
		t.Fatalf("direction groups: %+v", got.Destinations)
	}
	empty := buildNetfilterRows([]Event{before, after, alf, nettop}, since, asOf)
	if empty.EventRows != 0 || empty.FirstTS != nil || empty.LastTS != nil || empty.PerApp == nil || empty.Destinations == nil || empty.UnsignedOutbound.Rows == nil || empty.OddPorts.Rows == nil || empty.OddPorts.Policy != "policy_unusual_port" {
		t.Fatalf("empty does not mean missing arrays or timestamps: %+v", empty)
	}
}

// Exact app/signer and destination tuples remain distinct. Sorting is bytewise,
// nullable fields sort first, and output pointers do not alias retained ports.
func TestNetfilterRowsGrouping(t *testing.T) {
	at := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	port80, port443 := 80, 443
	base := netfilterRowsEvent(at)
	base.App = "A"
	base.Port = &port443
	duplicate := base
	missingPort := base
	missingPort.Port = nil
	lowPort := base
	lowPort.Port = &port80
	host := base
	host.Host = "example.test"
	bucket := base
	bucket.Bucket = "other.test"
	class := base
	class.RemoteClass = "lan"
	signer := base
	signer.Signer = "Other"
	app := base
	app.App = "a"
	events := []Event{app, signer, class, bucket, host, base, lowPort, missingPort, duplicate}
	before, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	got := buildNetfilterRows(events, at, at.Add(time.Second))
	wantApps := []netfilterAppRow{
		{App: "A", Signer: "Developer", EventRows: 7, OutboundEventRows: 7, DistinctRetainedDestinations: 6},
		{App: "A", Signer: "Other", EventRows: 1, OutboundEventRows: 1, DistinctRetainedDestinations: 1},
		{App: "a", Signer: "Developer", EventRows: 1, OutboundEventRows: 1, DistinctRetainedDestinations: 1},
	}
	if !reflect.DeepEqual(got.PerApp, wantApps) {
		t.Fatalf("app groups: got %+v want %+v", got.PerApp, wantApps)
	}
	wantDestinations := []netfilterDestinationRow{
		{App: "A", Signer: "Developer", Direction: "outbound", RemoteClass: "internet", Bucket: "example.test", EventRows: 1},
		{App: "A", Signer: "Developer", Direction: "outbound", RemoteClass: "internet", Bucket: "example.test", Port: &port80, EventRows: 1},
		{App: "A", Signer: "Developer", Direction: "outbound", RemoteClass: "internet", Bucket: "example.test", Port: &port443, EventRows: 2},
		{App: "A", Signer: "Developer", Direction: "outbound", RemoteClass: "internet", Bucket: "other.test", Port: &port443, EventRows: 1},
		{App: "A", Signer: "Developer", Direction: "outbound", RemoteClass: "lan", Bucket: "example.test", Port: &port443, EventRows: 1},
		{App: "A", Signer: "Developer", Direction: "outbound", Host: &host.Host, RemoteClass: "internet", Bucket: "example.test", Port: &port443, EventRows: 1},
		{App: "A", Signer: "Other", Direction: "outbound", RemoteClass: "internet", Bucket: "example.test", Port: &port443, EventRows: 1},
		{App: "a", Signer: "Developer", Direction: "outbound", RemoteClass: "internet", Bucket: "example.test", Port: &port443, EventRows: 1},
	}
	if !reflect.DeepEqual(got.Destinations, wantDestinations) {
		t.Fatalf("destination groups: got %+v want %+v", got.Destinations, wantDestinations)
	}
	after, err := json.Marshal(events)
	if err != nil || string(before) != string(after) {
		t.Fatal("reducer changed retained input", err)
	}
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	if reversed := buildNetfilterRows(events, at, at.Add(time.Second)); !reflect.DeepEqual(got, reversed) {
		t.Fatal("input order changed aggregate")
	}
	port443 = 99
	if *got.Destinations[2].Port != 443 {
		t.Fatal("aggregate aliases input port")
	}
}

// Categories require explicit outbound direction and exact retained policy;
// nearby signer/class/label/reason/port changes cannot manufacture a finding.
func TestNetfilterRowsCategories(t *testing.T) {
	at := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	port := 4444
	base := netfilterRowsEvent(at)
	base.Port = &port
	for _, tc := range []struct {
		name          string
		change        func(*Event)
		unsigned, odd int
	}{
		{"policy", func(e *Event) {}, 0, 1},
		{"unsigned earlier policy", func(e *Event) { e.Signer = "unsigned"; e.Reason = "policy_unsigned_outbound" }, 1, 0},
		{"ad-hoc", func(e *Event) { e.Signer = "ad-hoc"; e.Reason = "policy_unsigned_outbound" }, 1, 0},
		{"raw-IP earlier policy", func(e *Event) { e.RemoteClass = "internet-raw-ip"; e.Reason = "policy_raw_ip" }, 0, 0},
		{"unsigned raw-IP", func(e *Event) { e.Signer = "unsigned"; e.RemoteClass = "internet-raw-ip"; e.Reason = "policy_raw_ip" }, 1, 0},
		{"signer substring", func(e *Event) { e.Signer = "unsigned-extra"; e.Reason = "policy_unsigned_outbound" }, 0, 0},
		{"class prefix", func(e *Event) {
			e.Signer = "unsigned"
			e.RemoteClass = "internet-extra"
			e.Reason = "policy_unsigned_outbound"
		}, 0, 0},
		{"LAN unsigned", func(e *Event) { e.Signer = "unsigned"; e.RemoteClass = "lan"; e.Reason = "policy_unsigned_outbound" }, 0, 0},
		{"inbound", func(e *Event) { e.Signer = "unsigned"; e.Kind = "inbound" }, 0, 0},
		{"missing direction", func(e *Event) { e.Signer = "unsigned"; e.Kind = "" }, 0, 0},
		{"unknown direction", func(e *Event) { e.Signer = "unsigned"; e.Kind = "unknown" }, 0, 0},
		{"wrong source", func(e *Event) { e.Source = "nettop" }, 0, 0},
		{"missing port", func(e *Event) { e.Port = nil }, 0, 0},
		{"8443", func(e *Event) { p := 8443; e.Port = &p }, 0, 0},
		{"noise label", func(e *Event) { e.Label = "noise" }, 0, 0},
		{"reason substring", func(e *Event) { e.Reason = "policy_unusual_port_extra" }, 0, 0},
		{"reason case", func(e *Event) { e.Reason = "POLICY_UNUSUAL_PORT" }, 0, 0},
		{"decoded reason", func(e *Event) { e.Reason = map[string]any{"kind": "policy_unusual_port"} }, 0, 1},
		{"structured reason", func(e *Event) {
			e.Reason = struct {
				Kind string `json:"kind"`
			}{"policy_unusual_port"}
		}, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := base
			tc.change(&e)
			got := buildNetfilterRows([]Event{e}, at, at.Add(time.Second))
			if got.UnsignedOutbound.EventRows != tc.unsigned || got.OddPorts.EventRows != tc.odd || len(got.UnsignedOutbound.Rows) != tc.unsigned || len(got.OddPorts.Rows) != tc.odd {
				t.Fatalf("categories: unsigned=%+v odd=%+v", got.UnsignedOutbound, got.OddPorts)
			}
		})
	}
	// Every admitted unusual service port is a positive control, not just 4444.
	var events []Event
	for _, p := range []int{9050, 9001, 31337, 1337, 6667, 4444} {
		e := base
		e.Port = &p
		events = append(events, e, e)
	}
	got := buildNetfilterRows(events, at, at.Add(time.Second))
	if got.OddPorts.EventRows != 12 || len(got.OddPorts.Rows) != 6 {
		t.Fatalf("unusual ports: %+v", got.OddPorts)
	}
	for i, p := range []int{1337, 4444, 6667, 9001, 9050, 31337} {
		row := got.OddPorts.Rows[i]
		if row.Port != p || row.EventRows != 2 || row.App != base.App || row.Signer != base.Signer {
			t.Fatalf("port row %d: %+v", i, row)
		}
	}
}

// Category counts group retained app/signer pairs rather than inferred identity;
// app/signer sort order and destination counts stay independent of input order.
func TestNetfilterRowsUnsignedGroups(t *testing.T) {
	at := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	var events []Event
	for _, pair := range [][2]string{{"B", "unsigned"}, {"A", "unsigned"}, {"A", "ad-hoc"}, {"A", "unsigned"}} {
		e := netfilterRowsEvent(at)
		e.App, e.Signer, e.Reason = pair[0], pair[1], "policy_unsigned_outbound"
		events = append(events, e)
	}
	got := buildNetfilterRows(events, at, at.Add(time.Second))
	want := netfilterCategory{EventRows: 4, Rows: []netfilterCategoryRow{
		{App: "A", Signer: "ad-hoc", EventRows: 1},
		{App: "A", Signer: "unsigned", EventRows: 2},
		{App: "B", Signer: "unsigned", EventRows: 1},
	}}
	if !reflect.DeepEqual(got.UnsignedOutbound, want) || got.OddPorts.EventRows != 0 {
		t.Fatalf("category grouping: %+v", got)
	}
}

// A destination preserves required nullable wire members, and each row type
// emits only its contracted members; this does not validate the full section.
func TestNetfilterRowsWireMembers(t *testing.T) {
	at := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	e := netfilterRowsEvent(at)
	e.Kind = ""
	got := buildNetfilterRows([]Event{e}, at, at.Add(time.Second))
	for _, tc := range []struct {
		name  string
		value any
		want  string
	}{
		{"destination", got.Destinations[0], `{"app":"/app","signer":"Developer","direction":"unknown","host":null,"remote_class":"internet","bucket":"example.test","port":null,"event_rows":1}`},
		{"app", got.PerApp[0], `{"app":"/app","signer":"Developer","event_rows":1,"outbound_event_rows":0,"unknown_direction_event_rows":1,"distinct_retained_destinations":1}`},
		{"empty category", got.UnsignedOutbound, `{"event_rows":0,"rows":[]}`},
		{"empty policy", got.OddPorts, `{"policy":"policy_unusual_port","event_rows":0,"rows":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.value)
			if err != nil || string(data) != tc.want {
				t.Fatalf("got %s err=%v want %s", data, err, tc.want)
			}
		})
	}
}
