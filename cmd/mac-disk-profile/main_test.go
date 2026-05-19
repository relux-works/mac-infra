package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/diskprofile"
)

func TestRunScanWritesJSONArtifact(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	jsonPath := filepath.Join(t.TempDir(), "scan.json")

	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--depth", "1", "--json", jsonPath, root}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "json: "+jsonPath) {
		t.Fatalf("stdout missing json path: %s", stdout.String())
	}
	if _, err := os.Stat(jsonPath); err != nil {
		t.Fatalf("json artifact missing: %v", err)
	}
}

func TestRunExplainPrintsAPFSCaveats(t *testing.T) {
	root := t.TempDir()
	var stdout, stderr bytes.Buffer

	code := run([]string{"explain", "--depth", "0", root}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run code = %d, stderr = %s", code, stderr.String())
	}
	for _, want := range []string{"apfs_hidden_space", "apfs_purgeable_space", "time_machine_snapshots"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout missing %q: %s", want, stdout.String())
		}
	}
}

func TestRunTopSelectorFlags(t *testing.T) {
	root := t.TempDir()
	mustWriteSizedFile(t, filepath.Join(root, "large.bin"), 4096)
	mustMkdir(t, filepath.Join(root, "cache"))
	mustWriteSizedFile(t, filepath.Join(root, "cache", "small.bin"), 512)

	var stdout, stderr bytes.Buffer
	code := run([]string{"top", "--files", "--limit", "2", "--no-default-excludes", root}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run top --files code = %d, stderr = %s", code, stderr.String())
	}
	text := stdout.String()
	if !strings.Contains(text, "== top files ==") || !strings.Contains(text, "LOGICAL") || !strings.Contains(text, "large.bin") {
		t.Fatalf("top --files output missing file table:\n%s", text)
	}
	if strings.Contains(text, "== top directories ==") {
		t.Fatalf("top --files printed directories:\n%s", text)
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"top", "--dirs", "--limit", "2", "--no-default-excludes", root}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run top --dirs code = %d, stderr = %s", code, stderr.String())
	}
	text = stdout.String()
	if !strings.Contains(text, "== top directories ==") || !strings.Contains(text, "cache") {
		t.Fatalf("top --dirs output missing directory table:\n%s", text)
	}
	if strings.Contains(text, "== top files ==") {
		t.Fatalf("top --dirs printed files:\n%s", text)
	}
}

func TestRunCommandsRejectMultiplePaths(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	for _, command := range []string{"scan", "top", "explain"} {
		t.Run(command, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run([]string{command, root, other}, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("run code = %d, want 2; stdout = %s stderr = %s", code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), "at most one path") {
				t.Fatalf("stderr missing path error: %s", stderr.String())
			}
		})
	}
}

func TestRunReadOnlyCommandsDoNotMutateScannedFiles(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "file.txt")
	mustWriteFile(t, target, "stable data")
	before := snapshotPath(t, target)

	commands := [][]string{
		{"scan", "--depth", "1", root},
		{"top", "--limit", "5", root},
		{"explain", "--depth", "1", root},
	}
	for _, args := range commands {
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("run %v code = %d, stderr = %s", args, code, stderr.String())
		}
	}

	after := snapshotPath(t, target)
	if after != before {
		t.Fatalf("file metadata changed: before=%#v after=%#v", before, after)
	}
}

func TestRunScanUsesDefaultAndExplicitExcludes(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "node_modules"))
	mustWriteFile(t, filepath.Join(root, "node_modules", "dep.js"), "generated")
	mustMkdir(t, filepath.Join(root, "skip-me"))
	mustWriteFile(t, filepath.Join(root, "skip-me", "data.txt"), "explicit")
	jsonPath := filepath.Join(t.TempDir(), "scan.json")

	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--depth", "1", "--exclude", "skip-me", "--json", jsonPath, root}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run code = %d, stderr = %s", code, stderr.String())
	}
	result := readScanResult(t, jsonPath)
	if entryChildExists(result.RootEntry, "node_modules") {
		t.Fatalf("node_modules present despite default excludes: %#v", result.RootEntry.Children)
	}
	if entryChildExists(result.RootEntry, "skip-me") {
		t.Fatalf("skip-me present despite explicit exclude: %#v", result.RootEntry.Children)
	}
	if !containsString(result.Options.Excludes, "node_modules") || !containsString(result.Options.Excludes, "skip-me") {
		t.Fatalf("effective excludes = %#v, want defaults plus explicit exclude", result.Options.Excludes)
	}
}

func TestRunScanNoDefaultExcludesAllowsGeneratedTrees(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "node_modules"))
	mustWriteFile(t, filepath.Join(root, "node_modules", "dep.js"), "generated")
	jsonPath := filepath.Join(t.TempDir(), "scan.json")

	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--depth", "1", "--no-default-excludes", "--json", jsonPath, root}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run code = %d, stderr = %s", code, stderr.String())
	}
	result := readScanResult(t, jsonPath)
	if !entryChildExists(result.RootEntry, "node_modules") {
		t.Fatalf("node_modules missing with --no-default-excludes: %#v", result.RootEntry.Children)
	}
	if containsString(result.Options.Excludes, "node_modules") {
		t.Fatalf("effective excludes = %#v, want no default excludes", result.Options.Excludes)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustWriteFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustWriteSizedFile(t *testing.T, path string, size int) {
	t.Helper()
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, size), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readScanResult(t *testing.T, path string) diskprofile.ScanResult {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result diskprofile.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func entryChildExists(parent diskprofile.Entry, name string) bool {
	for _, child := range parent.Children {
		if child.Name == name {
			return true
		}
	}
	return false
}

type pathSnapshot struct {
	size        int64
	mode        os.FileMode
	modUnixNano int64
}

func snapshotPath(t *testing.T, path string) pathSnapshot {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return pathSnapshot{
		size:        info.Size(),
		mode:        info.Mode(),
		modUnixNano: info.ModTime().UnixNano(),
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
