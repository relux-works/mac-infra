package security

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type coreFakeRunner struct {
	data []byte
	err  error
}

func (r coreFakeRunner) Run(context.Context, string, ...string) ([]byte, error) { return r.data, r.err }

// A real planted IOC name and shell marker are detected by production collectors;
// adjacent harmless names and comments containing a secret never leak to output.
func TestIOCPlantedAndHarmlessControl(t *testing.T) {
	dir := fixtureDir(t)
	shell := filepath.Join(dir, "zshrc")
	os.WriteFile(shell, []byte("# secret-private-marker\necho safe"), 0600)
	run := func() Check {
		return scanIOC(context.Background(), coreFakeRunner{}, DefaultRules(), []string{dir}, nil, []string{shell})
	}
	clean := run()
	for _, f := range clean.Findings {
		if f.Code == "ioc_match" {
			t.Fatal("harmless flagged")
		}
	}
	os.Mkdir(filepath.Join(dir, ".xm5my-planted"), 0700)
	os.WriteFile(shell, []byte("# secret-private-marker\nairportd -c abc"), 0600)
	c := run()
	hits := c.Data["matches"].(map[string]int)
	if hits["mini-miner-dir"] != 1 || hits["mini-airport"] != 1 {
		t.Fatal(hits)
	}
	data, _ := json.Marshal(c)
	if strings.Contains(string(data), "secret-private-marker") || strings.Contains(string(data), "abc") {
		t.Fatal("raw content leaked")
	}
	denied := scanIOC(context.Background(), coreFakeRunner{err: errors.New("secret-private-marker")}, DefaultRules(), []string{filepath.Join(dir, "missing")}, nil, nil)
	if denied.Status != "partial" {
		t.Fatal(denied)
	}
	data, _ = json.Marshal(denied)
	if strings.Contains(string(data), "secret-private-marker") {
		t.Fatal("error leaked")
	}
}

// Invalid rule targets/globs are refused while a bounded fixed-target plugin
// matches without echoing its potentially sensitive pattern.
func TestIOCPluginClosedTarget(t *testing.T) {
	if validateRules([]Rule{{"x", "arbitrary-path", "/etc/passwd"}}) == nil || validateRules([]Rule{{"x", "tmp-name", "["}}) == nil {
		t.Fatal("bad plugin accepted")
	}
	dir := fixtureDir(t)
	os.WriteFile(filepath.Join(dir, "plugin-match"), nil, 0600)
	c := scanIOC(context.Background(), coreFakeRunner{}, []Rule{{"custom", "tmp-name", "plugin-match"}}, []string{dir}, nil, nil)
	if c.Data["matches"].(map[string]int)["custom"] != 1 {
		t.Fatal(c)
	}
}

// Invalid combined rule sets must not disable the default sweep; distinct
// plugin IDs remain accepted alongside the built-in rules.
func TestMergeIOCRules(t *testing.T) {
	if _, err := MergeRules([]Rule{{"mini-miner-dir", "tmp-name", "x"}}); err == nil {
		t.Fatal("duplicate built-in rule ID accepted")
	}
	r, err := MergeRules([]Rule{{"custom", "tmp-name", "x"}})
	if err != nil || len(r) != len(DefaultRules())+1 {
		t.Fatal(r, err)
	}
}
