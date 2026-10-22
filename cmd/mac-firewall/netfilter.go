package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/relux-works/mac-infra/internal/security/journal"
	"github.com/relux-works/mac-infra/internal/security/netfilterctl"
)

const netfilterUsage = `usage:
mac-firewall netfilter kill    --journal-dir DIR --protect-list FILE --app-binary PATH --actor A --reason R (--flow ID | [--app P] [--host H] [--port N])
mac-firewall netfilter block   --journal-dir DIR --protect-list FILE --app-binary PATH --actor A --reason R [--app P] [--host H] [--port N] --for DUR
mac-firewall netfilter unblock --journal-dir DIR --protect-list FILE --app-binary PATH --actor A --rule ID
mac-firewall netfilter reported --journal-dir DIR --actor A --ref SEQ --event EVENT_ID
mac-firewall netfilter list    --app-binary PATH --actor A
mac-firewall netfilter status  --journal-dir DIR --app-binary PATH

kill/block/unblock journal the intent before anything is sent; the protect-list
(root-owned) must exist. Output is JSON. Exit 0 ok, 1 refused/failed, 2 usage.`

// appRunner runs the signed NetFilter app binary with a deadline and a
// bounded output.
func appRunner(bin string) netfilterctl.Runner {
	return func(ctx context.Context, args []string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
		var out bytes.Buffer
		cmd.Stdout = &limitedWriter{w: &out, n: 1 << 20}
		err := cmd.Run()
		return out.Bytes(), err
	}
}

type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > l.n {
		l.w.Write(p[:l.n])
		l.n = 0
		return len(p), nil
	}
	l.n -= len(p)
	return l.w.Write(p)
}

var netfilterRun = appRunner

func runNetfilter(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, netfilterUsage)
		return 2
	}
	op := args[0]
	if op == "help" || op == "--help" {
		fmt.Fprintln(out, netfilterUsage)
		return 0
	}
	f := flag.NewFlagSet("netfilter "+op, flag.ContinueOnError)
	f.SetOutput(errOut)
	journalDir := f.String("journal-dir", "", "journal directory (owner-only)")
	protectPath := f.String("protect-list", "", "root-owned protect-list")
	appBin := f.String("app-binary", "", "NetFilter.app/Contents/MacOS/NetFilter")
	actor := f.String("actor", "", "who acts")
	reason := f.String("reason", "", "classifier verdict or rule")
	flow := f.String("flow", "", "flow id")
	app := f.String("app", "", "app path or signing id")
	host := f.String("host", "", "hostname or IP")
	port := f.Int("port", 0, "remote port")
	dur := f.Duration("for", 0, "block duration")
	rule := f.String("rule", "", "block rule id")
	ref := f.Uint64("ref", 0, "report_pending seq")
	event := f.String("event", "", "posted event id")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		fmt.Fprintln(errOut, netfilterUsage)
		return 2
	}
	printJSON := func(v any, ok bool) int {
		_ = json.NewEncoder(out).Encode(v)
		if ok {
			return 0
		}
		return 1
	}
	need := func(vals ...string) bool {
		for _, v := range vals {
			if v == "" {
				fmt.Fprintln(errOut, netfilterUsage)
				return false
			}
		}
		return true
	}
	openJournal := func() (*journal.Journal, error) {
		if !filepath.IsAbs(*journalDir) {
			return nil, fmt.Errorf("--journal-dir must be absolute")
		}
		return journal.Open(*journalDir, journal.Capacity)
	}
	switch op {
	case "kill", "block", "unblock":
		if !need(*journalDir, *protectPath, *appBin, *actor) || (op != "unblock" && !need(*reason)) {
			return 2
		}
		req := netfilterctl.Request{Op: op, Actor: *actor, Reason: *reason, FlowID: *flow, Target: netfilterctl.Target{App: *app, Host: *host, Port: *port}, Duration: *dur, RuleID: *rule}
		if err := req.Validate(); err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
		protect, err := netfilterctl.LoadProtectList(*protectPath)
		if err != nil {
			return printJSON(netfilterctl.Result{Error: err.Error()}, false)
		}
		j, err := openJournal()
		if err != nil {
			return printJSON(netfilterctl.Result{Error: "journal: " + err.Error()}, false)
		}
		res := netfilterctl.Execute(context.Background(), req, protect, j, netfilterRun(*appBin), time.Now)
		return printJSON(res, res.OK)
	case "reported":
		if !need(*journalDir, *actor, *event) || *ref == 0 {
			return 2
		}
		j, err := openJournal()
		if err != nil {
			return printJSON(map[string]any{"ok": false, "error": err.Error()}, false)
		}
		e, err := netfilterctl.Reported(j, *actor, *ref, *event, time.Now())
		if err != nil {
			return printJSON(map[string]any{"ok": false, "error": err.Error()}, false)
		}
		return printJSON(map[string]any{"ok": true, "entry": e}, true)
	case "list":
		if !need(*appBin, *actor) {
			return 2
		}
		raw, err := netfilterRun(*appBin)(context.Background(), []string{"list", "--actor", *actor})
		var v any
		if json.Unmarshal(bytes.TrimSpace(raw), &v) != nil {
			msg := "no valid answer from NetFilter"
			if err != nil {
				msg += ": " + err.Error()
			}
			return printJSON(map[string]any{"ok": false, "error": msg}, false)
		}
		ok, _ := v.(map[string]any)["ok"].(bool)
		return printJSON(v, ok)
	case "status":
		if !need(*journalDir, *appBin) {
			return 2
		}
		raw, appErr := netfilterRun(*appBin)(context.Background(), []string{"status"})
		status := map[string]any{"app_status": string(bytes.TrimSpace(raw)), "app_ok": appErr == nil}
		j, err := openJournal()
		if err != nil {
			status["journal_error"] = err.Error()
			return printJSON(status, false)
		}
		entries, err := j.Read()
		jstat := map[string]any{"entries": len(entries), "capacity": journal.Capacity}
		if err != nil {
			jstat["error"] = err.Error()
		} else {
			jstat["chain_ok"] = journal.Verify(entries) == nil
			pending := 0
			done := map[uint64]bool{}
			for _, e := range entries {
				if e.Kind == "report_done" {
					done[e.Ref] = true
				}
			}
			for _, e := range entries {
				if e.Kind == "report_pending" && !done[e.Seq] {
					pending++
				}
			}
			jstat["reports_pending"] = pending
			if n := len(entries); n > 0 {
				jstat["last_seq"] = entries[n-1].Seq
				jstat["last_hash"] = entries[n-1].Hash
			}
		}
		status["journal"] = jstat
		return printJSON(status, appErr == nil && err == nil && jstat["chain_ok"] == true)
	}
	fmt.Fprintln(errOut, netfilterUsage)
	return 2
}
