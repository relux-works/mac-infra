package netnone

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

type snapshot map[string]string

// JSON CLIs have emitted both arrays and newline-delimited objects. Reject
// malformed/unknown evidence instead of equating two incomplete snapshots.
func objects(data []byte) ([]map[string]json.RawMessage, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("empty JSON evidence")
	}
	var result []map[string]json.RawMessage
	if data[0] == '[' {
		err := json.Unmarshal(data, &result)
		return result, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var row map[string]json.RawMessage
		err := dec.Decode(&row)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if row == nil {
			return nil, errors.New("null JSON evidence")
		}
		result = append(result, row)
	}
	return result, nil
}
func jsonField(row map[string]json.RawMessage, name string) (json.RawMessage, bool) {
	for k, v := range row {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return nil, false
}
func fieldString(row map[string]json.RawMessage, name string) (string, error) {
	raw, ok := jsonField(row, name)
	if !ok {
		return "", fmt.Errorf("missing %s in JSON evidence", name)
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil || v == "" {
		return "", fmt.Errorf("invalid %s in JSON evidence", name)
	}
	return v, nil
}
func (s *session) snapshot(ctx context.Context) (snapshot, error) {
	snap := snapshot{}
	r, err := checked(s.e.Runner.Run(ctx, Command{Name: "docker", Args: []string{"context", "ls", "--format", "json"}, Env: s.e.UserEnv, Timeout: 20 * time.Second}))
	if err != nil {
		return nil, err
	}
	rows, err := objects(r.Stdout)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		name, err := fieldString(row, "Name")
		if err != nil {
			return nil, err
		}
		raw, ok := jsonField(row, "Current")
		if !ok {
			return nil, errors.New("missing context Current")
		}
		var current bool
		if err = json.Unmarshal(raw, &current); err != nil {
			return nil, err
		}
		key := "context:" + name
		if _, exists := snap[key]; exists {
			return nil, errors.New("duplicate context")
		}
		inspect, err := checked(s.e.Runner.Run(ctx, Command{Name: "docker", Args: []string{"context", "inspect", name}, Env: s.e.UserEnv, Timeout: 20 * time.Second}))
		if err != nil {
			return nil, err
		}
		if !json.Valid(inspect.Stdout) {
			return nil, errors.New("invalid context inspect evidence")
		}
		sum := sha256.Sum256(inspect.Stdout)
		snap[key] = fmt.Sprint(current) + ":" + hex.EncodeToString(sum[:])
	}
	if len(rows) == 0 {
		return nil, errors.New("no docker contexts in snapshot")
	}
	for _, rel := range []string{".docker/config.json", ".colima/ssh_config", ".ssh/config"} {
		data, err := os.ReadFile(filepath.Join(s.home, rel))
		if errors.Is(err, os.ErrNotExist) {
			snap[rel] = "missing"
			continue
		}
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		snap[rel] = hex.EncodeToString(sum[:])
	}
	socket := filepath.Join(s.home, ".colima/docker.sock")
	st, err := os.Lstat(socket)
	if errors.Is(err, os.ErrNotExist) {
		snap[".colima/docker.sock"] = "missing"
	} else if err != nil {
		return nil, err
	} else if st.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(socket)
		if err != nil {
			return nil, err
		}
		snap[".colima/docker.sock"] = "link:" + target
	} else {
		identity, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, errors.New("socket stat identity unavailable")
		}
		snap[".colima/docker.sock"] = fmt.Sprintf("device=%d inode=%d mode=%v", identity.Dev, identity.Ino, st.Mode())
	}
	r, err = checked(s.e.Runner.Run(ctx, Command{Name: "colima", Args: []string{"list", "--json"}, Env: s.e.UserEnv, Timeout: 20 * time.Second}))
	if err != nil {
		return nil, err
	}
	// A successful Colima list may emit no objects on a fresh installation.
	if len(bytes.TrimSpace(r.Stdout)) == 0 {
		rows = nil
	} else {
		rows, err = objects(r.Stdout)
		if err != nil {
			return nil, err
		}
	}
	for _, row := range rows {
		name, err := fieldString(row, "name")
		if err != nil {
			return nil, err
		}
		if name == Profile {
			continue
		}
		status, err := fieldString(row, "status")
		if err != nil {
			return nil, err
		}
		key := "profile:" + name
		if _, ok := snap[key]; ok {
			return nil, errors.New("duplicate colima profile")
		}
		snap[key] = status
	}
	// Inspect only the default home, never the tool-private Colima namespace.
	configs, err := filepath.Glob(filepath.Join(s.home, ".colima", "*", "colima.yaml"))
	if err != nil {
		return nil, err
	}
	for _, path := range configs {
		if filepath.Base(filepath.Dir(path)) == Profile {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		rel, err := filepath.Rel(s.home, path)
		if err != nil {
			return nil, err
		}
		snap[rel] = hex.EncodeToString(sum[:])
	}
	return snap, nil
}
func snapshotDiff(a, b snapshot) string {
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	var diff []string
	for k := range keys {
		av, aok := a[k]
		bv, bok := b[k]
		if av != bv || aok != bok {
			diff = append(diff, fmt.Sprintf("%s: %q -> %q", k, av, bv))
		}
	}
	sort.Strings(diff)
	return strings.Join(diff, "; ")
}

type verdict struct {
	check, expected, observed string
	pass                      bool
}

func probeLines(output string) (string, string) {
	var dns, tcp string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "dns=") {
			if dns != "" {
				return "duplicate DNS result", ""
			}
			dns = line
		}
		if strings.HasPrefix(line, "tcp=") {
			if tcp != "" {
				return "", "duplicate TCP result"
			}
			tcp = line
		}
	}
	return dns, tcp
}
func deniedTCP(s string) bool {
	return strings.HasPrefix(s, "tcp=fail:") && (strings.Contains(s, "Network is unreachable") || strings.HasPrefix(s, "tcp=fail:java.net.NoRouteToHostException:"))
}
func materializeFixture(root string) error {
	err := fs.WalkDir(assets, "assets/fixture", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel("assets/fixture", path)
		if err != nil {
			return err
		}
		dest := filepath.Join(root, rel)
		if d.IsDir() {
			return os.MkdirAll(dest, 0755)
		}
		data, err := assets.ReadFile(path)
		if err != nil {
			return err
		}
		mode := os.FileMode(0644)
		if d.Name() == "gradlew" {
			mode = 0755
		}
		return os.WriteFile(dest, data, mode)
	})
	if err != nil {
		return err
	}
	probe, err := assets.ReadFile("assets/Probe.java")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "Probe.java"), probe, 0644)
}
func (s *session) selftest(ctx context.Context, o Options) error {
	before, err := s.snapshot(ctx)
	if err != nil {
		return fmt.Errorf("selftest before snapshot: %w", err)
	}
	scratch, err := os.MkdirTemp(s.state, "selftest-")
	if err != nil {
		return err
	}
	// Preserve qualification XML and fixture for inspection alongside the report.
	o.Repo = filepath.Join(scratch, "fixture")
	o.Out = filepath.Join(scratch, "out")
	o.Task = "test"
	o.Toolchain = ""
	if err = materializeFixture(o.Repo); err != nil {
		return err
	}
	if err = os.Mkdir(o.Out, 0755); err != nil {
		return err
	}
	o.Repo, err = directory(o.Repo)
	if err != nil {
		return err
	}
	o.Out, err = directory(o.Out)
	if err != nil {
		return err
	}
	var checks []verdict
	add := func(check, expected, observed string, pass bool) {
		checks = append(checks, verdict{check, expected, observed, pass})
	}
	workErr := s.lifecycle(ctx, o, func() error {
		image, networked, err := s.prep(ctx, o, toolchainID{SHA: "base"}, true)
		if err != nil {
			return err
		}
		dns, tcp := probeLines(string(networked.Stdout))
		add("prep DNS", "dns=ok", dns, dns == "dns=ok")
		add("prep TCP", "tcp=ok", tcp, tcp == "tcp=ok")
		warm := regexpPrepExit(string(networked.Stdout))
		add("prep fixture", "task exit 0", fmt.Sprint(warm), warm == 0)
		probeOptions := o
		probeOptions.Out = ""
		args := append(s.deniedArgs(probeOptions, image, "java"), "/src/Probe.java")
		probe, probeErr := s.call(ctx, "docker", args...)
		dns, tcp = probeLines(string(probe.Stdout))
		add("run DNS", "dns=fail:java.net.UnknownHostException", dns, probeErr == nil && probe.ExitCode == 0 && dns == "dns=fail:java.net.UnknownHostException")
		add("run TCP", "unreachable network", tcp, probeErr == nil && probe.ExitCode == 0 && deniedTCP(tcp))
		stamp, runErr := s.runTests(ctx, o, image)
		var f *failure
		expectedFailure := errors.As(runErr, &f) && f.code == 1
		add("run fixture", "task fails", fmt.Sprint(runErr), expectedFailure)
		offline, network, detail := inspectJUnit(filepath.Join(o.Out, stamp))
		add("OfflineTest", "passed", detail, offline)
		add("NetworkTest", "network exception failure", detail, network)
		if runErr != nil && !expectedFailure {
			return runErr
		}
		return nil
	})
	// lifecycle has already stopped with an independent context. A cancelled work
	// context must not skip the after snapshot or turn unknown evidence into pass.
	snapCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	after, snapErr := s.snapshot(snapCtx)
	diff := "identical"
	same := snapErr == nil && reflect.DeepEqual(before, after)
	if snapErr != nil {
		diff = snapErr.Error()
	} else if !same {
		diff = snapshotDiff(before, after)
	}
	add("shared state", "identical before/after", diff, same)
	stopped, stopErr := s.profile(snapCtx)
	add("lifecycle", "completed and stopped", fmt.Sprintf("work=%v; state=%s; verification=%v", workErr, stopped, stopErr), workErr == nil && stopErr == nil && stopped == "stopped")
	fmt.Fprintln(s.e.Out, "| check | expected | observed | pass/fail |\n| --- | --- | --- | --- |")
	passed := true
	clean := func(v string) string { return strings.NewReplacer("|", "\\|", "\n", " ", "\r", " ").Replace(v) }
	for _, v := range checks {
		mark := "pass"
		if !v.pass {
			mark = "fail"
			passed = false
		}
		fmt.Fprintf(s.e.Out, "| %s | %s | %s | %s |\n", clean(v.check), clean(v.expected), clean(v.observed), mark)
	}
	if !passed {
		var f *failure
		if errors.As(workErr, &f) && f.code == 3 {
			return workErr
		}
		return fail(1, "selftest failed; inspect verdict table")
	}
	return nil
}

type junitCase struct {
	Class    string `xml:"classname,attr"`
	Name     string `xml:"name,attr"`
	Failures []struct {
		Type    string `xml:"type,attr"`
		Message string `xml:"message,attr"`
		Text    string `xml:",chardata"`
	} `xml:"failure"`
	Errors []struct {
		Type    string `xml:"type,attr"`
		Message string `xml:"message,attr"`
		Text    string `xml:",chardata"`
	} `xml:"error"`
	Skipped *struct{} `xml:"skipped"`
}

func inspectJUnit(root string) (bool, bool, string) {
	offline, network := 0, 0
	expected := map[string]int{"arithmetic": 0, "buildPackageWasCopied": 0}
	offOK, netOK := true, true
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".xml") || !strings.Contains(filepath.ToSlash(path), "/build/test-results/") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, 8<<20+1))
		if err != nil {
			return err
		}
		if len(data) > 8<<20 {
			return errors.New("JUnit XML too large")
		}
		dec := xml.NewDecoder(bytes.NewReader(data))
		for {
			tok, err := dec.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			start, ok := tok.(xml.StartElement)
			if !ok || start.Name.Local != "testcase" {
				continue
			}
			var c junitCase
			if err = dec.DecodeElement(&c, &start); err != nil {
				return err
			}
			switch c.Class {
			case "OfflineTest":
				offline++
				name := strings.TrimSuffix(c.Name, "()")
				if _, ok := expected[name]; !ok {
					offOK = false
				} else {
					expected[name]++
				}
				offOK = offOK && len(c.Failures) == 0 && len(c.Errors) == 0 && c.Skipped == nil
			case "NetworkTest":
				network++
				good := strings.TrimSuffix(c.Name, "()") == "repositoryReachable" && c.Skipped == nil && len(c.Failures)+len(c.Errors) > 0
				for _, f := range c.Failures {
					good = good && networkFailure(f.Type, f.Message, f.Text)
				}
				for _, f := range c.Errors {
					good = good && networkFailure(f.Type, f.Message, f.Text)
				}
				netOK = netOK && good
			}
		}
		return nil
	})
	if err != nil {
		return false, false, err.Error()
	}
	offlinePass := expected["arithmetic"] == 1 && expected["buildPackageWasCopied"] == 1 && offOK
	networkFail := network == 1 && netOK
	return offlinePass, networkFail, fmt.Sprintf("OfflineTest cases=%d arithmetic=%d buildPackageWasCopied=%d pass=%t; NetworkTest cases=%d network-fail=%t", offline, expected["arithmetic"], expected["buildPackageWasCopied"], offlinePass, network, networkFail)
}

var exceptionClass = regexp.MustCompile(`\b(?:[A-Za-z_$][A-Za-z0-9_$]*\.)+[A-Za-z_$][A-Za-z0-9_$]*(?:Exception|Error)\b`)

// Only failure body text supplies a missing type; a message may merely mention
// an expected exception and must not supply its identity.
func networkFailure(kind, message, text string) bool {
	if kind == "" {
		kind = exceptionClass.FindString(text)
		if kind == "" {
			return false
		}
	}
	return typedNetworkException(kind, message+" "+text)
}

func networkException(text string) bool { return typedNetworkException("", text) }
func typedNetworkException(kind, text string) bool {
	lower := strings.ToLower(text)
	for _, bad := range []string{"could not resolve", "could not download", "dependency resolution", "dependency-resolution", "no cached version", "could not find", "resolve dependencies"} {
		if strings.Contains(lower, bad) {
			return false
		}
	}
	if kind == "" {
		kind = exceptionClass.FindString(text)
	}
	switch kind {
	case "java.net.UnknownHostException", "java.net.NoRouteToHostException":
		return true
	case "java.net.SocketException":
		return strings.Contains(text, "Network is unreachable")
	}
	return false
}
