package toolsecret

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type CLI struct {
	Backend             Backend
	Stdout, Stderr      io.Writer
	StdinTTY, StdoutTTY bool
	AuditPath           string
	Now                 func() time.Time
	Actor               string
	LookupEnv           func(string) (string, bool)
}
type cliError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
}
type envelope struct {
	OK      bool      `json:"ok"`
	Command string    `json:"command"`
	Result  any       `json:"result,omitempty"`
	Error   *cliError `json:"error,omitempty"`
}
type paths []string

func (p *paths) String() string { return strings.Join(*p, ",") }
func (p *paths) Set(s string) error {
	if !filepath.IsAbs(s) {
		return fmt.Errorf("--keep needs an absolute path")
	}
	*p = append(*p, s)
	return nil
}

const usage = "mac-tool-secret [--json] inventory [--keychain PATH] [--service-prefix P] [--all --owner-sitting --out FILE] | bind --service S --account A --owner PATH [--keychain PATH] [--dry-run] [--owner-sitting] [--keep PATH]... [--owner-decision REF] | verify --service S --account A --owner PATH [--keychain PATH] | verify-audit [--audit-log FILE] [--expected-head SHA256]"

func IsTerminal(f *os.File) bool { return terminalFD(int(f.Fd())) }

func (c CLI) Run(ctx context.Context, args []string) int {
	jsonMode := false
	var filtered []string
	for _, a := range args {
		if a == "--json" {
			jsonMode = true
		} else {
			filtered = append(filtered, a)
		}
	}
	command := ""
	if len(filtered) > 0 {
		command = filtered[0]
		filtered = filtered[1:]
	}
	emit := func(result any, err error, exit int) int {
		e := envelope{OK: err == nil, Command: command, Result: result}
		if err != nil {
			code := "operation_failed"
			var r *Refusal
			if errors.As(err, &r) {
				code = r.Code
				exit = 3
			}
			if exit == 2 {
				code = "usage"
			}
			e.Error = &cliError{code, err.Error(), usage}
		}
		if jsonMode {
			if json.NewEncoder(c.Stdout).Encode(e) != nil {
				return 1
			}
		} else if err != nil {
			fmt.Fprintf(c.Stderr, "%s: %s\n", e.Error.Code, e.Error.Message)
		} else {
			b, _ := json.MarshalIndent(result, "", "  ")
			fmt.Fprintln(c.Stdout, string(b))
		}
		return exit
	}
	if command == "help" || command == "--help" || command == "-h" {
		return emit(map[string]string{"usage": usage}, nil, 0)
	}
	if command == "verify-audit" {
		fs := flag.NewFlagSet(command, flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		path := fs.String("audit-log", c.AuditPath, "audit log")
		expected := fs.String("expected-head", "", "external head pin")
		if err := fs.Parse(filtered); err != nil {
			return emit(nil, err, 2)
		}
		if fs.NArg() != 0 {
			return emit(nil, fmt.Errorf("unexpected positional arguments"), 2)
		}
		if *path == "" {
			var err error
			*path, err = DefaultAuditPath()
			if err != nil {
				return emit(nil, err, 1)
			}
		}
		if !filepath.IsAbs(*path) {
			return emit(nil, fmt.Errorf("audit path must be absolute"), 2)
		}
		head, err := VerifyAudit(*path, *expected)
		if err != nil {
			return emit(nil, err, 1)
		}
		return emit(head, nil, 0)
	}
	if command != "inventory" && command != "bind" && command != "verify" {
		return emit(nil, fmt.Errorf("expected inventory, bind or verify"), 2)
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	k := fs.String("keychain", "", "keychain file")
	service, account, ownerPath, prefix := "", "", "", ""
	ownerDecision, outPath := "", ""
	var keep paths
	dry, sitting, all := false, false, false
	if command == "inventory" {
		fs.StringVar(&prefix, "service-prefix", "", "service prefix")
		fs.BoolVar(&all, "all", false, "include all services; local file only")
		fs.StringVar(&outPath, "out", "", "new local 0600 output file")
	} else {
		fs.StringVar(&service, "service", "", "service")
		fs.StringVar(&account, "account", "", "account")
		fs.StringVar(&ownerPath, "owner", "", "owner executable")
	}
	if command == "bind" {
		fs.BoolVar(&dry, "dry-run", false, "print plan only")
		fs.Var(&keep, "keep", "explicit plaintext-release exception")
		fs.StringVar(&ownerDecision, "owner-decision", "", "audited decision allowing unsafe kept application")
	}
	if command == "bind" || command == "inventory" {
		fs.BoolVar(&sitting, "owner-sitting", false, "owner present on an unmultiplexed terminal")
	}
	if err := fs.Parse(filtered); err != nil {
		return emit(nil, err, 2)
	}
	if fs.NArg() != 0 {
		return emit(nil, fmt.Errorf("unexpected positional arguments"), 2)
	}
	if command != "inventory" && (service == "" || account == "" || !filepath.IsAbs(ownerPath)) {
		return emit(nil, fmt.Errorf("--service, --account and absolute --owner are required"), 2)
	}
	if *k != "" && !filepath.IsAbs(*k) {
		return emit(nil, fmt.Errorf("--keychain must be absolute"), 2)
	}
	lookup := c.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	if sitting && MultiplexerPresent(lookup) {
		return emit(nil, refuse("multiplexer_refused", "--owner-sitting is refused while TMUX or STY is set; use the owner's direct terminal"), 3)
	}
	if ownerDecision != "" && strings.TrimSpace(ownerDecision) == "" {
		return emit(nil, fmt.Errorf("--owner-decision needs a reference"), 2)
	}
	if outPath != "" && !filepath.IsAbs(outPath) {
		return emit(nil, fmt.Errorf("--out must be an absolute new local file"), 2)
	}
	if command == "inventory" && all {
		if !sitting || !c.StdinTTY || !c.StdoutTTY {
			return emit(nil, refuse("owner_sitting_required", "full inventory requires --owner-sitting and both TTYs"), 3)
		}
		if outPath == "" {
			return emit(nil, refuse("local_output_required", "--all requires --out /absolute/new/local/file; no full inventory on stdout"), 3)
		}
	}
	// Gate before even opening a keychain. --dry-run performs metadata queries only.
	if command == "bind" && !dry && (!sitting || !c.StdinTTY || !c.StdoutTTY) {
		return emit(nil, refuse("owner_sitting_required", "bind requires --owner-sitting and TTYs on stdin and stdout; use --dry-run to inspect"), 3)
	}
	if err := c.Backend.Startup(ctx); err != nil {
		return emit(nil, err, 1)
	}
	var owner Owner
	if command != "inventory" {
		var err error
		owner, err = c.Backend.Owner(ctx, ownerPath)
		if err != nil {
			return emit(nil, err, 1)
		}
		if err = ValidateOwner(owner); err != nil {
			return emit(nil, err, 3)
		}
	}
	items, err := c.Backend.Inventory(ctx, *k)
	if err != nil {
		return emit(nil, err, 1)
	}
	if command == "inventory" {
		reports := []InventoryItem{}
		owners := map[string]Owner{}
		queried := map[string]bool{}
		for _, item := range items {
			if (all || KnownService(item.Service)) && strings.HasPrefix(item.Service, prefix) {
				report := Inspect(item)
				for _, acl := range item.ReleaseACLs {
					if !CanReleasePlaintext(acl) {
						continue
					}
					for _, a := range acl.Applications {
						if ClassifyRequirement(a.Requirement) != Anchored || IsGenericApplication(a) || AppleInternal(a) || !filepath.IsAbs(a.Path) {
							continue
						}
						if !queried[a.Path] {
							queried[a.Path] = true
							current, e := c.Backend.Owner(ctx, a.Path)
							if e == nil {
								owners[a.Path] = current
							}
						}
						if current, ok := owners[a.Path]; ok {
							checked := InspectForOwner(item, current)
							for _, f := range checked.Flags {
								if !slices.Contains(report.Flags, f) {
									report.Flags = append(report.Flags, f)
								}
							}
						}
					}
				}
				reports = append(reports, report)
			}
		}
		if outPath != "" {
			if err := WriteLocalInventory(outPath, envelope{OK: true, Command: command, Result: reports}); err != nil {
				return emit(nil, err, 1)
			}
			return 0 // Full listing is written exclusively to the local file, even in JSON mode.
		}
		return emit(reports, nil, 0)
	}
	var found []Item
	for _, item := range items {
		if item.Service == service && item.Account == account {
			found = append(found, item)
		}
	}
	if len(found) != 1 {
		return emit(nil, refuse("item_not_unique", fmt.Sprintf("expected one existing item, found %d", len(found))), 3)
	}
	if command == "verify" {
		reasons := Verify(found[0], owner)
		result := struct {
			Verified bool     `json:"verified"`
			Reasons  []string `json:"reasons"`
		}{len(reasons) == 0, append([]string{}, reasons...)}
		if len(reasons) > 0 {
			return emit(result, refuse("verification_failed", strings.Join(reasons, "; ")), 3)
		}
		return emit(result, nil, 0)
	}
	kept := map[string]Owner{}
	for _, path := range keep {
		current, e := c.Backend.Owner(ctx, path)
		if e == nil {
			kept[path] = current
		}
	}
	plan, err := PlanBind(found[0], owner, BindOptions{Keep: keep, KeepOwners: kept, OwnerDecision: ownerDecision})
	if err != nil {
		return emit(nil, err, 3)
	}
	if dry {
		return emit(plan, nil, 0)
	}
	// JSON-escape all metadata even on a terminal, so item labels cannot inject
	// control sequences into the authorization preview.
	preview, _ := json.Marshal(plan)
	if _, err = fmt.Fprintf(c.Stderr, "Authorize exactly this item, owner requirement and partition list (one attempt, 60s deadline):\n%s\n", preview); err != nil {
		return emit(nil, err, 1)
	}
	path := c.AuditPath
	if path == "" {
		path, err = DefaultAuditPath()
		if err != nil {
			return emit(nil, err, 1)
		}
	}
	audit, err := OpenAudit(path)
	if err != nil {
		return emit(nil, err, 1)
	}
	defer audit.Close()
	now := c.Now
	if now == nil {
		now = time.Now
	}
	actor := c.Actor
	if actor == "" {
		actor = fmt.Sprintf("uid:%d", os.Getuid())
	}
	record := AuditRecord{Time: now().UTC(), Actor: actor, Outcome: "intent", Plan: plan}
	if err = AppendAudit(audit, record); err != nil {
		return emit(nil, err, 1)
	}
	err = c.Backend.Apply(ctx, *k, plan, true)
	record.Time = now().UTC()
	record.Outcome = "applied"
	if err != nil {
		record.Outcome = "failed_or_unknown"
	}
	if auditErr := AppendAudit(audit, record); auditErr != nil {
		return emit(nil, fmt.Errorf("mutation outcome %s; audit append failed: %w", record.Outcome, auditErr), 1)
	}
	if err != nil {
		return emit(nil, err, 1)
	}
	return emit(plan, nil, 0)
}
