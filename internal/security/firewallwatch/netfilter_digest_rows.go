package firewallwatch

import (
	"cmp"
	"slices"
	"time"
)

type netfilterAppRow struct {
	App                          string `json:"app"`
	Signer                       string `json:"signer"`
	EventRows                    int    `json:"event_rows"`
	OutboundEventRows            int    `json:"outbound_event_rows"`
	UnknownDirectionEventRows    int    `json:"unknown_direction_event_rows"`
	DistinctRetainedDestinations int    `json:"distinct_retained_destinations"`
}

type netfilterDestinationRow struct {
	App         string  `json:"app"`
	Signer      string  `json:"signer"`
	Direction   string  `json:"direction"`
	Host        *string `json:"host"`
	RemoteClass string  `json:"remote_class"`
	Bucket      string  `json:"bucket"`
	Port        *int    `json:"port"`
	EventRows   int     `json:"event_rows"`
}

type netfilterCategoryRow struct {
	App       string `json:"app"`
	Signer    string `json:"signer"`
	EventRows int    `json:"event_rows"`
}

type netfilterCategory struct {
	EventRows int                    `json:"event_rows"`
	Rows      []netfilterCategoryRow `json:"rows"`
}

type netfilterPolicyRow struct {
	App       string `json:"app"`
	Signer    string `json:"signer"`
	Port      int    `json:"port"`
	EventRows int    `json:"event_rows"`
}

type netfilterPolicyCategory struct {
	Policy    string               `json:"policy"`
	EventRows int                  `json:"event_rows"`
	Rows      []netfilterPolicyRow `json:"rows"`
}

// netfilterRows contains only retained observations. Coverage, collection state,
// journal availability and full-flow capabilities must be supplied separately.
type netfilterRows struct {
	EventRows                 int
	OutboundEventRows         int
	UnknownDirectionEventRows int
	FirstTS                   *time.Time
	LastTS                    *time.Time
	PerApp                    []netfilterAppRow
	Destinations              []netfilterDestinationRow
	UnsignedOutbound          netfilterCategory
	OddPorts                  netfilterPolicyCategory
}

type netfilterAppKey struct{ app, signer string }

// Empty host and zero port are the stored null forms; validated retained state
// admits neither a non-null empty host nor a service port of zero.
type netfilterDestinationKey struct {
	netfilterAppKey
	direction, host, remoteClass, bucket string
	port                                 int
}

type netfilterPolicyKey struct {
	netfilterAppKey
	port int
}

// buildNetfilterRows reduces already shape-validated retained state for an
// inclusive window. It neither reclassifies observations nor touches the store.
// A caller must validate state and window bounds before constructing wire output.
func buildNetfilterRows(events []Event, since, asOf time.Time) netfilterRows {
	out := netfilterRows{
		PerApp: []netfilterAppRow{}, Destinations: []netfilterDestinationRow{},
		UnsignedOutbound: netfilterCategory{Rows: []netfilterCategoryRow{}},
		OddPorts:         netfilterPolicyCategory{Policy: "policy_unusual_port", Rows: []netfilterPolicyRow{}},
	}
	apps := make(map[netfilterAppKey]netfilterAppRow)
	destinations := make(map[netfilterDestinationKey]int)
	unsigned := make(map[netfilterAppKey]int)
	ports := make(map[netfilterPolicyKey]int)
	for _, e := range events {
		if e.Source != SourceNetfilter || wallBefore(e.TS, since) || wallBefore(asOf, e.TS) {
			continue
		}
		out.EventRows++
		at := e.TS.UTC()
		if out.FirstTS == nil || wallBefore(at, *out.FirstTS) {
			out.FirstTS = &at
		}
		if out.LastTS == nil || wallBefore(*out.LastTS, at) {
			out.LastTS = &at
		}
		appKey := netfilterAppKey{e.App, e.Signer}
		app := apps[appKey]
		app.App, app.Signer = e.App, e.Signer
		app.EventRows++
		direction := "unknown"
		switch e.Kind {
		case "outbound":
			direction = "outbound"
			out.OutboundEventRows++
			app.OutboundEventRows++
		case "inbound":
			direction = "inbound"
		default:
			out.UnknownDirectionEventRows++
			app.UnknownDirectionEventRows++
		}
		port := 0
		if e.Port != nil {
			port = *e.Port
		}
		key := netfilterDestinationKey{appKey, direction, e.Host, e.RemoteClass, e.Bucket, port}
		if destinations[key] == 0 {
			app.DistinctRetainedDestinations++
		}
		destinations[key]++
		apps[appKey] = app
		if direction != "outbound" {
			continue
		}
		if (e.Signer == "unsigned" || e.Signer == "ad-hoc") && (e.RemoteClass == "internet" || e.RemoteClass == "internet-raw-ip") {
			out.UnsignedOutbound.EventRows++
			unsigned[appKey]++
		}
		if e.Label == "decide" && reasonKind(e.Reason) == out.OddPorts.Policy {
			switch port {
			case 4444, 6667, 1337, 31337, 9001, 9050:
				out.OddPorts.EventRows++
				ports[netfilterPolicyKey{appKey, port}]++
			}
		}
	}
	for _, row := range apps {
		out.PerApp = append(out.PerApp, row)
	}
	for k, count := range destinations {
		row := netfilterDestinationRow{App: k.app, Signer: k.signer, Direction: k.direction, RemoteClass: k.remoteClass, Bucket: k.bucket, EventRows: count}
		if k.host != "" {
			host := k.host
			row.Host = &host
		}
		if k.port != 0 {
			port := k.port
			row.Port = &port
		}
		out.Destinations = append(out.Destinations, row)
	}
	for k, count := range unsigned {
		out.UnsignedOutbound.Rows = append(out.UnsignedOutbound.Rows, netfilterCategoryRow{k.app, k.signer, count})
	}
	for k, count := range ports {
		out.OddPorts.Rows = append(out.OddPorts.Rows, netfilterPolicyRow{k.app, k.signer, k.port, count})
	}
	slices.SortFunc(out.PerApp, func(a, b netfilterAppRow) int {
		return compareNetfilterApp(a.App, a.Signer, b.App, b.Signer)
	})
	slices.SortFunc(out.Destinations, func(a, b netfilterDestinationRow) int {
		if c := compareNetfilterApp(a.App, a.Signer, b.App, b.Signer); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Direction, b.Direction); c != 0 {
			return c
		}
		if c := compareNetfilterNullable(a.Host, b.Host); c != 0 {
			return c
		}
		if c := cmp.Compare(a.RemoteClass, b.RemoteClass); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Bucket, b.Bucket); c != 0 {
			return c
		}
		return compareNetfilterNullable(a.Port, b.Port)
	})
	slices.SortFunc(out.UnsignedOutbound.Rows, func(a, b netfilterCategoryRow) int {
		return compareNetfilterApp(a.App, a.Signer, b.App, b.Signer)
	})
	slices.SortFunc(out.OddPorts.Rows, func(a, b netfilterPolicyRow) int {
		if c := compareNetfilterApp(a.App, a.Signer, b.App, b.Signer); c != 0 {
			return c
		}
		return cmp.Compare(a.Port, b.Port)
	})
	return out
}

func compareNetfilterApp(appA, signerA, appB, signerB string) int {
	if c := cmp.Compare(appA, appB); c != 0 {
		return c
	}
	return cmp.Compare(signerA, signerB)
}

func compareNetfilterNullable[T cmp.Ordered](a, b *T) int {
	if a == nil {
		if b == nil {
			return 0
		}
		return -1
	}
	if b == nil {
		return 1
	}
	return cmp.Compare(*a, *b)
}
