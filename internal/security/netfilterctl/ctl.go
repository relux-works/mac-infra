// Package netfilterctl is the journal-first operator side of the netfilter
// kill path (spec-kill-path.md, spec-journal.md on STORY-261023-qbc86k): it
// checks the protect-list, journals the intent before anything is sent,
// drives the signed NetFilter app, journals the result and produces the
// Russian incident report for the owner.
package netfilterctl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/relux-works/mac-infra/internal/security/journal"
)

// MaxBlock mirrors the extension's cap on one block.
const MaxBlock = 24 * time.Hour

// ProtectEntry and ProtectList mirror the extension's protect-list schema
// (apps/netfilter/Shared/Enforcement.swift); matching must stay identical.
type ProtectEntry struct {
	AppPath       *string `json:"app_path,omitempty"`
	AppPathPrefix *string `json:"app_path_prefix,omitempty"`
	SigningID     *string `json:"signing_id,omitempty"`
	HostSuffix    *string `json:"host_suffix,omitempty"`
	Reason        string  `json:"reason"`
}

type ProtectList struct {
	Schema  string         `json:"schema"`
	Entries []ProtectEntry `json:"entries"`
}

// LoadProtectList reads and strictly validates the root-owned protect-list.
func LoadProtectList(path string) (ProtectList, error) {
	var p ProtectList
	raw, err := os.ReadFile(path)
	if err != nil {
		return p, fmt.Errorf("protect-list unavailable (enforcement off): %w", err)
	}
	if len(raw) > 65536 {
		return p, errors.New("protect-list larger than 64 KiB")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&p); err != nil || d.More() {
		return p, errors.New("protect-list invalid")
	}
	if p.Schema != "mac-infra.netfilter-protect/v1" || len(p.Entries) == 0 {
		return p, errors.New("protect-list invalid: schema or empty")
	}
	for _, e := range p.Entries {
		n := 0
		for _, m := range []*string{e.AppPath, e.AppPathPrefix, e.SigningID, e.HostSuffix} {
			if m != nil {
				if *m == "" {
					return p, errors.New("protect-list invalid: empty matcher")
				}
				n++
			}
		}
		if n != 1 || e.Reason == "" {
			return p, errors.New("protect-list invalid: each entry needs exactly one matcher and a reason")
		}
	}
	return p, nil
}

// Protects returns the reason a target is protected, or "". The target's app
// is compared as a path and as a signing id; its host as a name.
func (p ProtectList) Protects(t Target) string {
	host := strings.ToLower(t.Host)
	for _, e := range p.Entries {
		switch {
		case e.AppPath != nil && t.App == *e.AppPath,
			e.AppPathPrefix != nil && t.App != "" && strings.HasPrefix(t.App, *e.AppPathPrefix),
			e.SigningID != nil && t.App == *e.SigningID,
			e.HostSuffix != nil && host != "" && (host == strings.ToLower(*e.HostSuffix) || strings.HasSuffix(host, "."+strings.ToLower(*e.HostSuffix))):
			return e.Reason
		}
	}
	return ""
}

// Target is what a kill or block applies to.
type Target struct {
	App  string `json:"app,omitempty"`
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
}

func (t Target) String() string {
	parts := []string{}
	if t.App != "" {
		parts = append(parts, "app="+t.App)
	}
	if t.Host != "" {
		parts = append(parts, "host="+t.Host)
	}
	if t.Port != 0 {
		parts = append(parts, "port="+strconv.Itoa(t.Port))
	}
	return strings.Join(parts, " ")
}

// Request is one operator action.
type Request struct {
	Op       string // kill, block, unblock
	Actor    string
	Reason   string
	FlowID   string
	Target   Target
	Duration time.Duration
	RuleID   string
}

// Response is the extension's JSON answer as the app prints it.
type Response struct {
	OK     bool              `json:"ok"`
	Error  *string           `json:"error"`
	Killed []json.RawMessage `json:"killed"`
	Rule   *struct {
		ID     string `json:"id"`
		Expiry any    `json:"expiry"`
	} `json:"rule"`
	Rules         []json.RawMessage `json:"rules"`
	KillableFlows int               `json:"killable_flows"`
}

// Runner executes the signed NetFilter app with arguments and returns its
// stdout. Tests replace it.
type Runner func(ctx context.Context, args []string) ([]byte, error)

// Result is what Execute reports back to the CLI.
type Result struct {
	OK            bool           `json:"ok"`
	Response      *Response      `json:"response,omitempty"`
	Error         string         `json:"error,omitempty"`
	Intent        *journal.Entry `json:"intent,omitempty"`
	Outcome       *journal.Entry `json:"result,omitempty"`
	ReportPending *journal.Entry `json:"report_pending,omitempty"`
	IncidentRU    string         `json:"incident_ru,omitempty"`
}

// Validate checks a request before anything else happens.
func (r Request) Validate() error {
	if r.Actor == "" || len(r.Actor) > 64 {
		return errors.New("--actor is required")
	}
	switch r.Op {
	case "alarm", "warning":
		if r.FlowID != "" || r.Duration != 0 || r.RuleID != "" {
			return errors.New(r.Op + " takes only --reason and an optional target")
		}
	case "kill":
		if (r.FlowID == "") == (r.Target == Target{}) {
			return errors.New("kill needs exactly one of --flow or a target (--app/--host/--port)")
		}
	case "block":
		if r.Target.App == "" && r.Target.Host == "" {
			return errors.New("block needs --app or --host")
		}
		if r.Duration <= 0 || r.Duration > MaxBlock {
			return errors.New("block needs --for in (0, 24h]")
		}
	case "unblock":
		if r.RuleID == "" {
			return errors.New("unblock needs --rule")
		}
	default:
		return fmt.Errorf("unknown op %q", r.Op)
	}
	if r.Op != "unblock" && (r.Reason == "" || len(r.Reason) > 120) {
		return errors.New("--reason is required (classifier verdict or rule)")
	}
	if r.Target.Port < 0 || r.Target.Port > 65535 || len(r.Target.App) > 256 || len(r.Target.Host) > 128 || len(r.FlowID) > 64 || len(r.RuleID) > 64 {
		return errors.New("target out of bounds")
	}
	return nil
}

func (r Request) appArgs() []string {
	args := []string{r.Op, "--actor", r.Actor}
	if r.FlowID != "" {
		args = append(args, "--flow", r.FlowID)
	}
	if r.Target.App != "" {
		args = append(args, "--app", r.Target.App)
	}
	if r.Target.Host != "" {
		args = append(args, "--host", r.Target.Host)
	}
	if r.Target.Port != 0 {
		args = append(args, "--port", strconv.Itoa(r.Target.Port))
	}
	if r.Op == "block" {
		args = append(args, "--for", strconv.FormatFloat(r.Duration.Seconds(), 'f', 0, 64))
	}
	if r.RuleID != "" {
		args = append(args, "--rule", r.RuleID)
	}
	return args
}

// Execute runs one kill, block or unblock: protect-list check, journal
// intent (fsynced), the app call, journal result, and for applied kills and
// blocks a report_pending entry plus the incident text. The app is never run
// unless the intent was journaled.
func Execute(ctx context.Context, r Request, protect ProtectList, j *journal.Journal, run Runner, now func() time.Time) Result {
	// The extension lowercases hosts; journal them the same way so the
	// watcher's reconciliation matches intent and action.
	r.Target.Host = strings.ToLower(r.Target.Host)
	if err := r.Validate(); err != nil {
		return Result{Error: err.Error()}
	}
	if r.Op == "alarm" || r.Op == "warning" {
		e, err := j.Append(journal.Entry{TS: now().UTC(), Kind: r.Op, Source: r.Reason, Actor: r.Actor, Target: r.Target.String(), Action: r.Op})
		if err != nil {
			return Result{Error: "journal write failed: " + err.Error()}
		}
		return Result{OK: true, Outcome: &e}
	}
	if r.Op != "unblock" {
		if why := protect.Protects(r.Target); why != "" {
			return Result{Error: "target is protected: " + why}
		}
	}
	intent := journal.Entry{TS: now().UTC(), Kind: r.Op + "_intent", Source: r.Reason, Actor: r.Actor, Target: r.Target.String(), Action: r.Op}
	if r.Op == "unblock" {
		intent.Kind, intent.Target = "unblock", "rule="+r.RuleID
	}
	if r.FlowID != "" {
		intent.Target = "flow=" + r.FlowID
	}
	if r.Op == "block" {
		exp := now().Add(r.Duration).UTC()
		intent.Expiry = &exp
	}
	written, err := j.Append(intent)
	if err != nil {
		return Result{Error: "journal write failed, nothing sent: " + err.Error()}
	}
	res := Result{Intent: &written}
	out, runErr := run(ctx, r.appArgs())
	var resp Response
	decodeErr := json.Unmarshal(bytes.TrimSpace(out), &resp)
	outcome := journal.Entry{TS: now().UTC(), Kind: r.Op + "_result", Source: r.Reason, Actor: r.Actor, Target: written.Target, Ref: written.Seq}
	if r.Op == "unblock" {
		outcome.Kind = "undo"
	}
	switch {
	case decodeErr != nil:
		outcome.Action = "error: no answer from the extension"
		res.Error = "no valid answer from NetFilter"
		if runErr != nil {
			res.Error += ": " + runErr.Error()
		}
	case !resp.OK:
		why := "refused"
		if resp.Error != nil {
			why = "refused: " + *resp.Error
		}
		outcome.Action = truncate(why, 150)
		res.Error = why
		res.Response = &resp
	default:
		res.Response = &resp
		res.OK = true
		switch r.Op {
		case "kill":
			outcome.Action = fmt.Sprintf("killed %d", len(resp.Killed))
		case "block":
			if resp.Rule != nil {
				outcome.Action = "blocked rule=" + resp.Rule.ID
				outcome.Undo = "mac-firewall netfilter unblock --rule " + resp.Rule.ID
				outcome.Expiry = intent.Expiry
			}
		case "unblock":
			outcome.Action = "unblocked " + r.RuleID
		}
	}
	result, err := j.Append(outcome)
	if err != nil {
		res.OK = false
		res.Error = strings.TrimSpace(res.Error + "; result not journaled: " + err.Error())
		return res
	}
	res.Outcome = &result
	if res.OK && r.Op != "unblock" {
		pending, err := j.Append(journal.Entry{TS: now().UTC(), Kind: "report_pending", Source: r.Reason, Actor: r.Actor, Target: result.Target, Action: "owner report pending", Ref: result.Seq})
		if err != nil {
			res.Error = "report_pending not journaled: " + err.Error()
		} else {
			res.ReportPending = &pending
		}
		res.IncidentRU = incident(r, resp, result)
	}
	return res
}

// Reported closes a report_pending entry once the owner post went out.
func Reported(j *journal.Journal, actor string, ref uint64, eventID string, now time.Time) (journal.Entry, error) {
	if actor == "" || eventID == "" || len(eventID) > 100 {
		return journal.Entry{}, errors.New("reported needs --actor, --ref and --event")
	}
	entries, err := j.Read()
	if err != nil {
		return journal.Entry{}, err
	}
	open := false
	for _, e := range entries {
		if e.Kind == "report_pending" && e.Seq == ref {
			open = true
		}
		if e.Kind == "report_done" && e.Ref == ref {
			return journal.Entry{}, fmt.Errorf("report for seq %d already done", ref)
		}
	}
	if !open {
		return journal.Entry{}, fmt.Errorf("no report_pending with seq %d in the journal window", ref)
	}
	return j.Append(journal.Entry{TS: now.UTC(), Kind: "report_done", Actor: actor, Target: "event=" + eventID, Action: "owner report posted", Ref: ref})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// incident is the owner post (Russian, plain): what, which app, where, why,
// who, how to undo, and the journal anchor.
func incident(r Request, resp Response, result journal.Entry) string {
	var b strings.Builder
	app, where := r.Target.App, r.Target.Host
	if app == "" {
		app = "любое"
	}
	if where == "" {
		where = "любой адрес"
	}
	if r.Target.Port != 0 {
		where += ":" + strconv.Itoa(r.Target.Port)
	}
	switch r.Op {
	case "kill":
		fmt.Fprintf(&b, "[mac-infra / netfilter] Разорвано соединение\n")
		if r.FlowID != "" {
			fmt.Fprintf(&b, "Что: разрыв соединения %s (разорвано: %d)\n", r.FlowID, len(resp.Killed))
		} else {
			fmt.Fprintf(&b, "Что: разрыв текущих соединений (разорвано: %d)\n", len(resp.Killed))
		}
	case "block":
		fmt.Fprintf(&b, "[mac-infra / netfilter] Блокировка новых соединений\n")
		fmt.Fprintf(&b, "Что: новые соединения блокируются до %s UTC, потом блокировка снимется сама\n", result.Expiry.Format("2006-01-02 15:04"))
	}
	fmt.Fprintf(&b, "Приложение: %s\nКуда: %s\nПочему: %s\nКто: %s\n", app, where, r.Reason, r.Actor)
	if result.Undo != "" {
		fmt.Fprintf(&b, "Как отменить: %s\n", result.Undo)
	} else {
		fmt.Fprintf(&b, "Как отменить: разрыв не откатывается; приложение может подключиться заново, блокировки нет\n")
	}
	fmt.Fprintf(&b, "Журнал: запись %d, hash %s", result.Seq, result.Hash[:12])
	return b.String()
}
