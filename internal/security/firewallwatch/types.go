// Package firewallwatch observes firewall activity and proposes labels only.
// It deliberately has no dependency on mac-infra-core or firewall mutations.
package firewallwatch

import (
	"fmt"
	"strings"
	"time"
)

type Item struct {
	ID         string  `json:"id,omitempty"`
	Kind       string  `json:"kind"`
	App        string  `json:"app"`
	Signer     string  `json:"signer"`
	Verdict    string  `json:"verdict"`
	LocalPort  *int    `json:"local_port,omitempty"`
	Remote     string  `json:"remote"`
	RemotePort *int    `json:"remote_port,omitempty"`
	MBOut      float64 `json:"mb_out"`
	Count      int     `json:"count"`
	Label      string  `json:"label,omitempty"`
	Source     string  `json:"source,omitempty"`
	Bucket     string  `json:"bucket,omitempty"`
	Spike      bool    `json:"-"`
}

type Neighbour struct {
	ID         string  `json:"id"`
	Similarity float64 `json:"similarity"`
}
type Decision struct {
	Label      string      `json:"proposed_label"`
	Reason     string      `json:"reason"`
	Neighbours []Neighbour `json:"neighbours,omitempty"`
}
type Event struct {
	TS          time.Time `json:"ts"`
	Source      string    `json:"source"`
	App         string    `json:"app"`
	Signer      string    `json:"signer"`
	Verdict     string    `json:"verdict"`
	Port        *int      `json:"port"`
	RemoteClass string    `json:"remote_class"`
	Bucket      string    `json:"bucket"`
	Counts      uint64    `json:"counts"`
	Label       string    `json:"proposed_label"`
	Reason      any       `json:"reason"`
	Mode        string    `json:"mode"`
}

const Instruction = "Instruct: Classify a macOS firewall event as routine noise, digest-worthy, or needing an allow/deny decision\nQuery: "

// Render preserves the benchmark feature representation, including quoted data.
func Render(it Item) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s flow; app=%q; signer=%q; verdict=%s; remote=%s", it.Kind, it.App, it.Signer, it.Verdict, it.Remote)
	if it.LocalPort != nil {
		fmt.Fprintf(&b, "; local_port=%d", *it.LocalPort)
	}
	if it.RemotePort != nil {
		fmt.Fprintf(&b, "; remote_port=%d", *it.RemotePort)
	}
	fmt.Fprintf(&b, "; mb_out=%g; count=%d", it.MBOut, it.Count)
	return b.String()
}

func port(it Item) *int {
	if it.LocalPort != nil {
		return it.LocalPort
	}
	return it.RemotePort
}
func validLabel(s string) bool { return s == "noise" || s == "digest" || s == "decide" }
