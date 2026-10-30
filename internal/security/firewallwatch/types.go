// Package firewallwatch observes firewall activity and proposes labels only.
// It deliberately has no dependency on mac-infra-core or firewall mutations.
package firewallwatch

import (
	"fmt"
	"strings"
	"time"
)

type Item struct {
	InspectionPath string  `json:"-"`
	ID             string  `json:"id,omitempty"`
	Kind           string  `json:"kind"`
	App            string  `json:"app"`
	Signer         string  `json:"signer"`
	Verdict        string  `json:"verdict"`
	LocalPort      *int    `json:"local_port,omitempty"`
	Remote         string  `json:"remote"`
	RemotePort     *int    `json:"remote_port,omitempty"`
	MBOut          float64 `json:"mb_out"`
	Count          int     `json:"count"`
	Label          string  `json:"label,omitempty"`
	Source         string  `json:"source,omitempty"`
	Bucket         string  `json:"bucket,omitempty"`
	// Host is the remote hostname of a netfilter flow (lowercase, no trailing dot).
	Host  string `json:"host,omitempty"`
	Spike bool   `json:"-"`
	// PID and ProcName are what nettop printed for the row's process (the
	// name raw, as nettop truncates it); Path is the path that process was
	// started from, resolved at sample time, or "" when it could not be
	// confirmed; ImageCDHash is the kernel's code directory hash of the image
	// it runs (processImage). None of them enters the classifier's rendering.
	PID         int    `json:"-"`
	ProcName    string `json:"-"`
	Path        string `json:"-"`
	ImageCDHash string `json:"-"`
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
	// Kind (direction) and Host are set for netfilter events only.
	Kind string `json:"kind,omitempty"`
	Host string `json:"host,omitempty"`
	// Path is the executable of a nettop event's process, when it was
	// confirmed at sample time; absent for other sources.
	Path   string `json:"path,omitempty"`
	Counts uint64 `json:"counts"`
	Label  string `json:"proposed_label"`
	Reason any    `json:"reason"`
	Mode   string `json:"mode"`
}

const Instruction = "Instruct: Classify a macOS firewall event as routine noise, digest-worthy, or needing an allow/deny decision\nQuery: "

// Render preserves the benchmark feature representation, including quoted data.
func Render(it Item) string {
	it = cleanItem(it)
	var b strings.Builder
	fmt.Fprintf(&b, "%s flow; app=%q; signer=%q; verdict=%s; remote=%s", it.Kind, it.App, it.Signer, it.Verdict, it.Remote)
	if it.Host != "" {
		fmt.Fprintf(&b, "; host=%q", it.Host)
	}
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
