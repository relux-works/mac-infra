package firewall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var ctx = context.Background()

func ownerConfig() Config {
	return Config{Schema: SchemaV1, AllowSignedBuiltin: ptr(true), AllowSignedDownloaded: ptr(true),
		Apps: AppsConfig{Mode: ModeListed}, Services: ServicesConfig{Disable: []string{"apache"}}}
}

// Claim: the real --listapps output captured on this host parses completely,
// including bundle-id entries; damaged variants are refused, not half-read.
func TestParseListAppsHostFixtureAndDamagedVariants(t *testing.T) {
	raw, err := os.ReadFile("testdata/listapps-host-261017.txt")
	if err != nil {
		t.Fatal(err)
	}
	apps, err := parseListApps(string(raw))
	if err != nil {
		t.Fatalf("host fixture: %v", err)
	}
	if len(apps) != 15 || apps[0] != (App{Name: "/usr/libexec/remoted", Allowed: true}) || apps[10].Name != "com.spotify.client" {
		t.Fatalf("host fixture parsed as %+v", apps)
	}
	blocked, err := parseListApps(renderListApps([]App{{Name: "/a b/x.app", Allowed: false}}))
	if err != nil || len(blocked) != 1 || blocked[0].Allowed || blocked[0].Name != "/a b/x.app" {
		t.Fatalf("blocked entry with a space: %+v, %v", blocked, err)
	}
	for name, damaged := range map[string]string{
		"total too high": strings.Replace(string(raw), "= 15", "= 16", 1),
		"unknown policy": strings.Replace(string(raw), "(Allow incoming connections)", "(Maybe incoming connections)", 1),
		"missing header": strings.SplitN(string(raw), "\n", 2)[1],
		"renumbered":     strings.Replace(string(raw), "2 : /usr/bin/python3", "7 : /usr/bin/python3", 1),
		"empty":          "",
	} {
		if _, err := parseListApps(damaged); err == nil {
			t.Errorf("%s: damaged app list was accepted", name)
		}
	}
}

// Claim: every state reader accepts exactly the known spellings and refuses
// anything else instead of guessing.
func TestStateParsersAcceptKnownOutputOnly(t *testing.T) {
	if on, all, err := parseGlobalState("Firewall is enabled. (State = 2)\n"); err != nil || !on || !all {
		t.Fatalf("state 2: %v %v %v", on, all, err)
	}
	if _, _, err := parseGlobalState("Firewall is maybe. (State = 3)"); err == nil {
		t.Fatal("unknown global state accepted")
	}
	if v, err := parseBlockAll("Firewall has block all state set to disabled.\n  \n"); err != nil || v {
		t.Fatalf("block all: %v %v", v, err)
	}
	if _, err := parseBlockAll("Firewall has block all state set to sometimes."); err == nil {
		t.Fatal("unknown block-all accepted")
	}
	if b, d, err := parseAllowSigned("Automatically allow built-in signed software ENABLED.\nAutomatically allow downloaded signed software DISABLED.\n"); err != nil || !b || d {
		t.Fatalf("allow signed: %v %v %v", b, d, err)
	}
	if _, _, err := parseAllowSigned("Automatically allow built-in signed software ENABLED.\nAutomatically allow built-in signed software ENABLED.\n"); err == nil {
		t.Fatal("duplicated signed-software line accepted")
	}
	overrides, err := parsePrintDisabled("disabled services = {\n\t\t\"org.apache.httpd\" => enabled\n\t\t\"com.x\" => true\n\t}\n\nlogin item associations = {\n}\n")
	if err != nil || overrides["org.apache.httpd"] || !overrides["com.x"] {
		t.Fatalf("print-disabled: %v %v", overrides, err)
	}
	if _, err := parsePrintDisabled("disabled services = {\n\t\"org.apache.httpd\" => enabled\n"); err == nil {
		t.Fatal("unterminated print-disabled accepted")
	}
}

// Claim: the config parser accepts the owner's first config and refuses
// unknown fields (including any attempt to say "enabled": false), trailing
// data, wrong schema, unclean paths, duplicates and unlisted services.
func TestParseConfigStrictness(t *testing.T) {
	valid := `{"schema":"mac-infra.firewall/v1","allow_signed_builtin":true,"apps":{"mode":"listed","allow":[],"block":[]},"services":{"disable":["apache"]}}`
	if _, err := ParseConfig([]byte(valid)); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	for name, raw := range map[string]string{
		"enabled false":   strings.Replace(valid, `"allow_signed_builtin"`, `"enabled":false,"allow_signed_builtin"`, 1),
		"trailing object": valid + `{}`,
		"wrong schema":    strings.Replace(valid, "/v1", "/v2", 1),
		"missing mode":    strings.Replace(valid, `"mode":"listed",`, "", 1),
		"relative path":   strings.Replace(valid, `"allow":[]`, `"allow":["Applications/X.app"]`, 1),
		"unclean path":    strings.Replace(valid, `"allow":[]`, `"allow":["/Applications/../X.app"]`, 1),
		"duplicate":       strings.Replace(valid, `"allow":[],"block":[]`, `"allow":["/X.app"],"block":["/X.app"]`, 1),
		"unknown service": strings.Replace(valid, `["apache"]`, `["sshd"]`, 1),
		"too large":       valid + strings.Repeat(" ", MaxConfigBytes),
	} {
		if _, err := ParseConfig([]byte(raw)); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
}

// Claim: on a host like this one the owner's first config plans exactly
// firewall on + Apache disable + Apache stop, with nothing loosened.
func TestOwnerFirstConfigPlan(t *testing.T) {
	plan, err := BuildPlan(ctx, ownerConfig(), hostLikeState(), fakeResolver{}, true)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, step := range plan.Steps {
		kinds = append(kinds, step.Kind)
		if step.Loosens {
			t.Errorf("step %s loosens", step.Kind)
		}
	}
	if got := strings.Join(kinds, ","); got != "global_on,service_disable,service_stop" {
		t.Fatalf("plan kinds = %s", got)
	}
	if plan.Steps[0].Undo != nil {
		t.Fatal("global_on must have no undo: the firewall stays on")
	}
}

// Claim: plan is a dry run; it reads the host and never runs a mutating
// command. Positive control: apply of the same config does mutate.
func TestPlanNeverMutates(t *testing.T) {
	host := newFakeHost(hostLikeState())
	report := Engine{Runner: host, Resolver: fakeResolver{}}.Plan(ctx, ownerConfig())
	if report.Outcome != OutcomePlanned || len(report.Plan.Steps) != 3 {
		t.Fatalf("plan report: %+v", report)
	}
	if m := host.mutations(); len(m) != 0 {
		t.Fatalf("plan ran mutating commands: %v", m)
	}
	control := newFakeHost(hostLikeState())
	Engine{Runner: control, Resolver: fakeResolver{}}.Apply(ctx, ownerConfig(), nil)
	if len(control.mutations()) == 0 {
		t.Fatal("control: apply ran no mutating command")
	}
}

// Claim: apply reaches the desired state with readback, and a second apply
// of the same config is a no-op.
func TestApplyThenIdempotent(t *testing.T) {
	host := newFakeHost(hostLikeState())
	engine := Engine{Runner: host, Resolver: fakeResolver{}}
	report := engine.Apply(ctx, ownerConfig(), nil)
	if report.Outcome != OutcomeApplied {
		t.Fatalf("apply: %+v", report)
	}
	if !host.state.Enabled || host.state.Services[0].Loaded || !host.state.Services[0].Disabled {
		t.Fatalf("host state after apply: %+v", host.state)
	}
	before := len(host.mutations())
	again := engine.Apply(ctx, ownerConfig(), nil)
	if again.Outcome != OutcomeNoChange || len(host.mutations()) != before {
		t.Fatalf("second apply: outcome %s, new mutations %d", again.Outcome, len(host.mutations())-before)
	}
}

// Claim: allowing an app requires an Apple-anchored signature; an unsigned
// app makes the whole apply refuse before any mutation, even mutations that
// would have been valid. Positive control: the signed app is allowed and
// its identity is recorded.
func TestLooseningRequiresAnchoredSignature(t *testing.T) {
	unsigned, signed := makeApp(t, "Unsigned.app"), makeApp(t, "Signed.app")
	resolver := fakeResolver{signed: map[string]AppIdentity{signed: {Identifier: "com.example.signed", TeamID: "TEAM123456"}}}

	cfg := ownerConfig()
	cfg.Apps.Allow = []string{unsigned}
	host := newFakeHost(hostLikeState())
	report := Engine{Runner: host, Resolver: resolver}.Apply(ctx, cfg, nil)
	if report.Outcome != OutcomeRefused || !strings.Contains(report.Error, "refusing to allow") {
		t.Fatalf("unsigned allow: %+v", report)
	}
	if m := host.mutations(); len(m) != 0 {
		t.Fatalf("refused apply mutated: %v", m)
	}

	cfg.Apps.Allow = []string{signed}
	control := newFakeHost(hostLikeState())
	report = Engine{Runner: control, Resolver: resolver}.Apply(ctx, cfg, nil)
	if report.Outcome != OutcomeApplied {
		t.Fatalf("signed allow: %+v", report)
	}
	var identity *AppIdentity
	for _, step := range report.Plan.Steps {
		if step.Kind == StepAppAddAllow {
			identity = step.Identity
		}
	}
	if identity == nil || identity.TeamID != "TEAM123456" {
		t.Fatalf("signed allow identity = %+v", identity)
	}
}

// Claim: blocking (tightening) needs no signature, and an already-allowed
// unsigned entry stays as it is because nothing is loosened.
func TestTighteningAndUnchangedEntriesNeedNoSignature(t *testing.T) {
	blocked, kept := makeApp(t, "Block.app"), makeApp(t, "Kept.app")
	state := hostLikeState()
	state.Apps = append(state.Apps, App{Name: kept, Allowed: true})
	cfg := ownerConfig()
	cfg.Apps = AppsConfig{Mode: ModeListed, Allow: []string{kept}, Block: []string{blocked}}
	host := newFakeHost(state)
	report := Engine{Runner: host, Resolver: fakeResolver{}}.Apply(ctx, cfg, nil)
	if report.Outcome != OutcomeApplied {
		t.Fatalf("apply: %+v", report)
	}
	if i := host.findApp(blocked); i < 0 || host.state.Apps[i].Allowed {
		t.Fatalf("blocked app state: %+v", host.state.Apps)
	}
}

// Claim: when a step fails mid-apply, every started step is undone in
// reverse and the readback equals the pre-apply state, except the firewall,
// which stays on.
func TestMidApplyFailureRollsBack(t *testing.T) {
	signed := makeApp(t, "Signed.app")
	cfg := ownerConfig()
	cfg.Stealth = ptr(true)
	cfg.Apps.Allow = []string{signed}
	host := newFakeHost(hostLikeState())
	host.failArgv[SocketFilterFW+" --unblockapp "+signed] = true
	pre := host.state.comparable()
	report := Engine{Runner: host, Resolver: fakeResolver{signed: map[string]AppIdentity{signed: {Identifier: "x"}}}}.Apply(ctx, cfg, nil)
	if report.Outcome != OutcomeRolledBack {
		t.Fatalf("outcome = %s (%s, drift %s)", report.Outcome, report.Error, report.Drift)
	}
	if host.state.comparable() != pre || !host.state.Enabled {
		t.Fatalf("after rollback: %s enabled=%v, want %s and enabled", host.state.comparable(), host.state.Enabled, pre)
	}
	if host.findApp(signed) >= 0 {
		t.Fatal("the half-added app entry was not removed")
	}
}

// Claim: a command that exits 0 without effect is caught by readback and
// rolled back; apply never reports success on an unverified state.
func TestReadbackMismatchRollsBack(t *testing.T) {
	cfg := ownerConfig()
	cfg.Stealth = ptr(true)
	host := newFakeHost(hostLikeState())
	host.ignoreArgv[Launchctl+" bootout system/org.apache.httpd"] = true
	report := Engine{Runner: host, Resolver: fakeResolver{}}.Apply(ctx, cfg, nil)
	if report.Outcome != OutcomeRolledBack || !strings.Contains(report.Error, "readback") {
		t.Fatalf("outcome = %s, error = %s", report.Outcome, report.Error)
	}
	if host.state.Stealth || host.state.Services[0].Disabled {
		t.Fatalf("state not restored: %+v", host.state)
	}
}

// Claim: when an undo also fails, the report says rollback_failed and names
// the drift instead of claiming a clean rollback.
func TestRollbackFailureReportsDrift(t *testing.T) {
	cfg := ownerConfig()
	cfg.Stealth = ptr(true)
	host := newFakeHost(hostLikeState())
	host.failArgv[Launchctl+" bootout system/org.apache.httpd"] = true
	host.failArgv[SocketFilterFW+" --setstealthmode off"] = true
	report := Engine{Runner: host, Resolver: fakeResolver{}}.Apply(ctx, cfg, nil)
	if report.Outcome != OutcomeRollbackFailed || !strings.Contains(report.Drift, "stealth=true") {
		t.Fatalf("outcome = %s, drift = %q", report.Outcome, report.Drift)
	}
}

// Claim: a failing pre-mutation hook (the audit write) refuses the apply
// with no mutation at all.
func TestBeforeMutationFailureRefuses(t *testing.T) {
	host := newFakeHost(hostLikeState())
	report := Engine{Runner: host, Resolver: fakeResolver{}}.Apply(ctx, ownerConfig(), func(Plan) error { return errors.New("audit unavailable") })
	if report.Outcome != OutcomeRefused || len(host.mutations()) != 0 {
		t.Fatalf("outcome %s, mutations %v", report.Outcome, host.mutations())
	}
}

// Claim: exact mode removes path entries missing from the config, keeps
// listed ones, and reports bundle-id entries as unmanaged instead of
// touching them.
func TestExactModeRemovesUnlistedPathEntries(t *testing.T) {
	kept := makeApp(t, "Kept.app")
	state := hostLikeState()
	state.Apps = append(state.Apps, App{Name: kept, Allowed: true})
	cfg := ownerConfig()
	cfg.Apps = AppsConfig{Mode: ModeExact, Allow: []string{kept}}
	plan, err := BuildPlan(ctx, cfg, state, fakeResolver{}, true)
	if err != nil {
		t.Fatal(err)
	}
	var removed []string
	for _, step := range plan.Steps {
		if step.Kind == StepAppRemove {
			removed = append(removed, step.Target)
		}
	}
	if strings.Join(removed, ",") != "/usr/sbin/cupsd" || strings.Join(plan.Unmanaged, ",") != "com.spotify.client" {
		t.Fatalf("removed %v, unmanaged %v", removed, plan.Unmanaged)
	}
}

// Claim: a config path matches an entry listed under its bundle id, so an
// app socketfilterfw reports by bundle id is not added a second time.
func TestBundleIDAliasMatchesExistingEntry(t *testing.T) {
	spotify := makeApp(t, "Spotify.app")
	cfg := ownerConfig()
	cfg.Apps.Allow = []string{spotify}
	resolver := fakeResolver{bundleIDs: map[string]string{spotify: "com.spotify.client"}}
	plan, err := BuildPlan(ctx, cfg, hostLikeState(), resolver, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range plan.Steps {
		if strings.HasPrefix(step.Kind, "app_") {
			t.Fatalf("unexpected app step %+v", step)
		}
	}
}

// Claim: missing paths and symlinks are refused during planning; a real
// directory at the same place is accepted (positive control).
func TestPlanRefusesMissingAndSymlinkPaths(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "Real.app")
	link := filepath.Join(dir, "Link.app")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"missing": filepath.Join(dir, "Missing.app"), "symlink": link} {
		cfg := ownerConfig()
		cfg.Apps.Block = []string{path}
		if _, err := BuildPlan(ctx, cfg, hostLikeState(), fakeResolver{}, true); err == nil {
			t.Errorf("%s path accepted", name)
		}
	}
	cfg := ownerConfig()
	cfg.Apps.Block = []string{real}
	if _, err := BuildPlan(ctx, cfg, hostLikeState(), fakeResolver{}, true); err != nil {
		t.Fatalf("control: real path refused: %v", err)
	}
}

// Claim: the exec allowlist is the last line of defence: it refuses
// turning the firewall off, unlisted services, unknown flags and unknown
// binaries, and accepts the commands the planner emits.
func TestAllowedArgv(t *testing.T) {
	refused := [][]string{
		{SocketFilterFW, "--setglobalstate", "off"},
		{SocketFilterFW, "--setloggingmode", "on"},
		{SocketFilterFW, "--add", "relative/path"},
		{SocketFilterFW, "--setstealthmode", "on", "extra"},
		{Launchctl, "bootout", "system/com.openssh.sshd"},
		{Launchctl, "bootstrap", "system", "/Library/LaunchDaemons/evil.plist"},
		{Launchctl, "kickstart", "-k", "system/org.apache.httpd"},
		{"/bin/sh", "-c", "true"},
		{Codesign, "--verify", "/Applications/X.app"},
	}
	for _, argv := range refused {
		if allowedArgv(argv[0], argv[1:]) {
			t.Errorf("allowed: %v", argv)
		}
	}
	accepted := [][]string{
		{SocketFilterFW, "--setglobalstate", "on"},
		{SocketFilterFW, "--blockapp", "/Applications/X.app"},
		{Launchctl, "bootout", "system/org.apache.httpd"},
		{Launchctl, "bootstrap", "system", "/System/Library/LaunchDaemons/org.apache.httpd.plist"},
		{Codesign, "--verify", "-R=anchor apple generic", "/Applications/X.app"},
		{Plutil, "-extract", "CFBundleIdentifier", "raw", "-o", "-", "/Applications/X.app/Contents/Info.plist"},
		append([]string{Lsof}, lsofListenerArgs...),
	}
	for _, argv := range accepted {
		if !allowedArgv(argv[0], argv[1:]) {
			t.Errorf("refused: %v", argv)
		}
	}
}

// Claim: keep-on enforcement turns a disabled firewall back on and verifies
// it; on an enabled firewall it does nothing.
func TestEnforceOn(t *testing.T) {
	host := newFakeHost(hostLikeState())
	report, acted := Engine{Runner: host}.EnforceOn(ctx)
	if !acted || report.Outcome != OutcomeEnforced || !host.state.Enabled {
		t.Fatalf("enforce on disabled: %+v acted=%v", report, acted)
	}
	before := len(host.mutations())
	report, acted = Engine{Runner: host}.EnforceOn(ctx)
	if acted || report.Outcome != OutcomeNoChange || len(host.mutations()) != before {
		t.Fatalf("enforce on enabled: %+v acted=%v", report, acted)
	}
}

// Claim: a seeded config describes the current state exactly, so applying
// it unchanged is a no-op; bundle-id entries are reported, not listed.
func TestSeedConfigRoundTrip(t *testing.T) {
	app := makeApp(t, "Seed.app")
	state := hostLikeState()
	state.Enabled = true
	state.Apps = []App{{Name: app, Allowed: false}, {Name: "com.spotify.client", Allowed: true}}
	cfg, unaddressable := SeedConfig(state)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(unaddressable, ",") != "com.spotify.client" || strings.Join(cfg.Apps.Block, ",") != app {
		t.Fatalf("seed: %+v, unaddressable %v", cfg.Apps, unaddressable)
	}
	host := newFakeHost(state)
	if report := (Engine{Runner: host, Resolver: fakeResolver{}}).Apply(ctx, cfg, nil); report.Outcome != OutcomeNoChange {
		t.Fatalf("seed apply: %+v", report)
	}
}
