// Command host-watch watches this Mac for the exec-gate stall class and alerts before the GUI dies.
//
// When syspolicyd (the exec-policy daemon) crash-loops, the kernel holds every exec of non-Apple
// code: agent tools, hooks and a2a itself hang, load climbs and finally WindowServer stops checking
// in. host-watch therefore observes with Apple binaries and in-process calls only, alerts the owner
// first through a macOS notification (/usr/bin/osascript), and sends a2a notices only while execs of
// non-Apple code work, with at most one a2a post outstanding. Its single automatic action is the
// exec-degraded flag (sysadmin/docs/host-health-degraded-flag.md). It never kills, restarts or changes foreign
// processes, launchd jobs or protection settings; children it starts and times out are its own.
//
// It is run by a user LaunchAgent. Every input is an explicit flag; there are no implicit defaults.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type options struct {
	reportsDirs                                   []string
	toolPrefixes                                  []string
	stateDir, flagPath, a2a, as, room, to         string
	dataVolume, fseventsLabel                     string
	interval, postTimeout, probeEvery, clearAfter time.Duration
	notify, once, dryRun                          bool
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--probe-exec" {
		return // the exec-latency probe target: start and exit at once
	}
	var o options
	var reports string
	var tools string
	flag.StringVar(&reports, "reports-dirs", "", "required: comma-separated diagnostic report directories (each Retired subdirectory is scanned too)")
	flag.StringVar(&tools, "tool-report-prefixes", "", "required: comma-separated binary names whose crash reports alert, e.g. mac-firewall,host-watch")
	flag.StringVar(&o.stateDir, "state-dir", "", "required: private state directory (state.json, events.jsonl, heartbeat)")
	flag.StringVar(&o.flagPath, "degraded-flag", "", "required: path of the exec-degraded flag file")
	flag.StringVar(&o.a2a, "a2a", "", "required: absolute path of the a2a binary")
	flag.StringVar(&o.as, "as", "", "required: a2a identity to post as")
	flag.StringVar(&o.room, "room", "", "required: a2a room")
	flag.StringVar(&o.to, "to", "", "required: comma-separated addressees")
	flag.StringVar(&o.dataVolume, "data-volume", "", "required: data volume mount point for the free-space check")
	flag.StringVar(&o.fseventsLabel, "fseventsd-watchdog-label", "", "required: user LaunchAgent label of the fseventsd watchdog")
	flag.DurationVar(&o.interval, "interval", 0, "required: loop interval, e.g. 15s")
	flag.DurationVar(&o.probeEvery, "probe-every", 0, "required: exec-latency probe interval, e.g. 60s")
	flag.DurationVar(&o.postTimeout, "post-timeout", 0, "required: hard timeout of one a2a post, e.g. 60s")
	flag.DurationVar(&o.clearAfter, "clear-after", 0, "required: healthy time before the degraded flag is removed, e.g. 10m")
	flag.BoolVar(&o.notify, "notify", false, "show macOS notifications (Apple-only channel)")
	flag.BoolVar(&o.once, "once", false, "observe only: run one read-only tick (no state, event log, heartbeat, flag, notification or a2a post) and exit")
	flag.BoolVar(&o.dryRun, "dry-run", false, "record alerts but do not notify, post or write the degraded flag")
	flag.Parse()
	for _, d := range strings.Split(reports, ",") {
		if d = strings.TrimSpace(d); d != "" {
			o.reportsDirs = append(o.reportsDirs, d)
		}
	}
	for _, p := range strings.Split(tools, ",") {
		if p = strings.TrimSpace(p); p != "" {
			o.toolPrefixes = append(o.toolPrefixes, p)
		}
	}
	if err := o.validate(); err != nil {
		fmt.Fprintln(os.Stderr, "host-watch:", err)
		os.Exit(2)
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "host-watch:", err)
		os.Exit(1)
	}
	w := newWatcher(o, liveSystem(o, self))
	for {
		if err := w.tick(time.Now().UTC()); err != nil {
			fmt.Fprintln(os.Stderr, "host-watch:", err)
			if o.once {
				os.Exit(1)
			}
		}
		if o.once {
			w.drain()
			return
		}
		time.Sleep(o.interval)
	}
}

func (o options) validate() error {
	var missing []string
	if len(o.reportsDirs) == 0 {
		missing = append(missing, "--reports-dirs")
	}
	if len(o.toolPrefixes) == 0 {
		missing = append(missing, "--tool-report-prefixes")
	}
	for _, kv := range [][2]string{{"state-dir", o.stateDir}, {"degraded-flag", o.flagPath}, {"a2a", o.a2a}, {"as", o.as}, {"room", o.room}, {"to", o.to}, {"data-volume", o.dataVolume}, {"fseventsd-watchdog-label", o.fseventsLabel}} {
		if kv[1] == "" {
			missing = append(missing, "--"+kv[0])
		}
	}
	for _, kv := range []struct {
		name string
		d    time.Duration
	}{{"interval", o.interval}, {"probe-every", o.probeEvery}, {"post-timeout", o.postTimeout}, {"clear-after", o.clearAfter}} {
		if kv.d <= 0 {
			missing = append(missing, "--"+kv.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required flags: %s", strings.Join(missing, " "))
	}
	for _, p := range o.toolPrefixes {
		if !toolPrefixRe.MatchString(p) {
			return errors.New("bad tool report prefix: " + p)
		}
	}
	paths := append([]string{o.stateDir, o.flagPath, o.a2a, o.dataVolume}, o.reportsDirs...)
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			return errors.New("paths must be absolute: " + p)
		}
	}
	canonical, err := canonicalFlagPath()
	if err != nil {
		return err
	}
	if o.flagPath != canonical {
		return fmt.Errorf("--degraded-flag must be exactly the contract path %s; consumers read only that path", canonical)
	}
	if err := checkNoSymlinks(canonical); err != nil {
		return err
	}
	return o.validateBounds()
}

// validateBounds enforces the agreed ranges of the timing flags.
func (o options) validateBounds() error {
	// A tick holds the queue while it posts: its post plus the output drain must end before the next
	// tick would count as an unobserved gap, or a timed-out post would reset recovery windows.
	if o.interval+o.postTimeout+drainAfterExit >= 2*o.interval+observeTimeout {
		return fmt.Errorf("--post-timeout %s too long for --interval %s: interval + post timeout + %s drain must stay below the %s gap limit", o.postTimeout, o.interval, drainAfterExit, 2*o.interval+observeTimeout)
	}
	for _, b := range []struct {
		name      string
		d, lo, hi time.Duration
	}{
		{"interval", o.interval, time.Second, time.Minute},
		{"probe-every", o.probeEvery, o.interval, 10 * time.Minute},
		{"post-timeout", o.postTimeout, time.Second, time.Minute},
		{"clear-after", o.clearAfter, 10 * time.Minute, 24 * time.Hour},
	} {
		if b.d < b.lo || b.d > b.hi {
			return fmt.Errorf("--%s %s outside [%s, %s]", b.name, b.d, b.lo, b.hi)
		}
	}
	return nil
}
