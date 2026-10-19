package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/relux-works/mac-infra/internal/security/firewallwatch"
)

const watchUsage = `mac-firewall watch run --config PATH
mac-firewall watch digest --config PATH --since DURATION [--json]
mac-firewall watch status --config PATH [--json]
mac-firewall watch classify --config PATH --fixtures FILE [--json]
Shadow mode only. No blocking or firewall changes. Exit 0 success, 1 failure, 2 usage.`

var startWatchBackend = firewallwatch.StartBackend

func runWatch(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, watchUsage)
		return 2
	}
	if args[0] == "help" || args[0] == "--help" {
		fmt.Fprintln(out, watchUsage)
		return 0
	}
	command := args[0]
	if command != "run" && command != "digest" && command != "status" && command != "classify" {
		fmt.Fprintln(errOut, watchUsage)
		return 2
	}
	f := flag.NewFlagSet("watch "+command, flag.ContinueOnError)
	f.SetOutput(errOut)
	config := f.String("config", "", "required private watch config")
	var asJSON bool
	var since, fixtures string
	if command != "run" {
		f.BoolVar(&asJSON, "json", false, "print JSON")
	}
	if command == "digest" {
		f.StringVar(&since, "since", "", "required positive Go duration")
	}
	if command == "classify" {
		f.StringVar(&fixtures, "fixtures", "", "labelled synthetic JSONL")
	}
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || *config == "" || (command == "classify" && fixtures == "") {
		fmt.Fprintln(errOut, watchUsage)
		return 2
	}
	var period time.Duration
	if command == "digest" {
		var e error
		period, e = time.ParseDuration(since)
		if e != nil || period <= 0 {
			fmt.Fprintln(errOut, "--since requires a positive duration")
			return 2
		}
	}
	c, e := firewallwatch.LoadConfig(*config)
	if e != nil {
		fmt.Fprintln(errOut, e)
		return 1
	}
	printJSON := func(v any) int {
		if e := json.NewEncoder(out).Encode(v); e != nil {
			return 1
		}
		return 0
	}
	if command == "status" || command == "digest" {
		s, e := firewallwatch.OpenStore(c)
		if e != nil {
			fmt.Fprintln(errOut, e)
			return 1
		}
		if command == "status" {
			if asJSON {
				return printJSON(s.Status())
			}
			fmt.Fprintf(out, "shadow: %s; backend healthy=%t (as of %s); unrecognized=%d; invalid_json=%d; last event=%s\n", s, s.State.BackendHealthy, s.State.Updated.Format(time.RFC3339), s.State.Parser.Unrecognized+s.State.NettopUnrecognized, s.State.Parser.Invalid, s.State.LastEvent.Format(time.RFC3339))
			return 0
		}
		groups := s.Digest(time.Now().Add(-period))
		if asJSON {
			return printJSON(groups)
		}
		for _, label := range []string{"noise", "digest", "decide"} {
			g := groups[label]
			fmt.Fprintf(out, "%s: %d — %s\n", label, g.Count, strings.Join(g.Apps, ", "))
		}
		return 0
	}
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	cl, e := firewallwatch.NewClassifier(c)
	if e != nil {
		fmt.Fprintln(errOut, e)
		return 1
	}
	stop, e := startWatchBackend(ctx, c)
	if e != nil {
		fmt.Fprintln(errOut, e)
		return 1
	}
	defer stop()
	if e = cl.Init(ctx); e != nil {
		fmt.Fprintln(errOut, "classifier unavailable; proposals fail to decide")
	}
	if command == "run" {
		if e = firewallwatch.Run(ctx, c, cl); e != nil {
			fmt.Fprintln(errOut, e)
			return 1
		}
		return 0
	}
	items, e := firewallwatch.LoadItems(fixtures)
	if e != nil {
		fmt.Fprintln(errOut, e)
		return 1
	}
	m := firewallwatch.Evaluate(ctx, items, cl.Classify)
	if asJSON {
		return printJSON(m)
	}
	fmt.Fprintf(out, "%s\nn=%d accuracy=%.4f macro_f1=%.4f decide→noise=%d latency p50=%.3fms p95=%.3fms unavailable=%d\n", m.Dataset, m.N, m.Accuracy, m.MacroF1, m.DecideToNoise, m.P50MS, m.P95MS, m.Unavailable)
	return 0
}
