package browserfacade

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGrepIsBoundedToNamedSiteCacheIgnoresUnrequestedSymlinksAndRefusesExplicit(t *testing.T) {
	root := t.TempDir()
	cache := Cache{Root: root}
	name, err := cache.Write("marketplace", "query", []map[string]string{{"id": "1", "title": "Blue lamp"}})
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.jsonl")
	if err := os.WriteFile(outside, []byte(`{"id":"2","title":"Blue secret outside"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "marketplace", "linked.jsonl")); err != nil {
		t.Fatal(err)
	}
	matches, err := cache.Grep("marketplace", GrepOptions{Pattern: "Blue", MaxMatches: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].File != name {
		t.Fatalf("matches=%#v", matches)
	}
	if _, err := cache.Grep("marketplace", GrepOptions{Pattern: "Blue", File: "../outside.jsonl", MaxMatches: 10}); ErrorCode(err) != "CACHE_SCOPE_REFUSED" {
		t.Fatalf("traversal error=%v", err)
	}
	if _, err := cache.Grep("marketplace", GrepOptions{Pattern: "Blue", File: "linked.jsonl", MaxMatches: 10}); ErrorCode(err) != "CACHE_SCOPE_REFUSED" {
		t.Fatalf("explicit final symlink error=%v", err)
	}
}

func TestGrepRefusesUnsanitizedCacheInsteadOfTreatingReadFailureAsAbsence(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "marketplace")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "bad.jsonl"), []byte(`{"title":"Authorization: Bearer abcdefghijklmnop"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := (Cache{Root: root}).Grep("marketplace", GrepOptions{Pattern: "anything", MaxMatches: 10})
	if err == nil || ErrorCode(err) != "SENSITIVE_RESPONSE_REFUSED" {
		t.Fatalf("error=%v", err)
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("malformed cache was treated as absence: %v", err)
	}
}

func TestCacheWriteRefusesUnsanitizedRecordsBeforeCreatingSiteCache(t *testing.T) {
	for name, value := range map[string]string{
		"github-token":  "ghp_012345678901234567890123456789012345",
		"gitlab-token":  "glpat-0123456789abcdefghijklmnop",
		"secret-url":    "https://shop.example/item?api_key=api-secret&signature=signed-secret",
		"uppercase-url": "HTTPS://SHOP.EXAMPLE/item?API_KEY=api-secret&SIGNATURE=signed-secret",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			_, err := (Cache{Root: root}).Write("marketplace", "unsafe", []map[string]string{{"title": value}})
			if ErrorCode(err) != "SENSITIVE_RESPONSE_REFUSED" {
				t.Fatalf("error=%v", err)
			}
			entries, readErr := os.ReadDir(root)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("unsafe cache path created: entries=%v err=%v", entries, readErr)
			}
		})
	}
}

func TestGrepRejectsDuplicateJSONKeysBeforeCanonicalRendering(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "marketplace")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	line := `{"title":"Bearer duplicate-shadow-secret","title":"safe lamp"}` + "\n"
	if err := os.WriteFile(filepath.Join(directory, "duplicate.jsonl"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := (Cache{Root: root}).Grep("marketplace", GrepOptions{Pattern: "lamp", MaxMatches: 10})
	if ErrorCode(err) != "SENSITIVE_RESPONSE_REFUSED" {
		t.Fatalf("duplicate cache error=%v", err)
	}
}

func TestGrepSupportsRegexCaseContextAndStrictMatchBound(t *testing.T) {
	root := t.TempDir()
	cache := Cache{Root: root}
	_, err := cache.Write("marketplace", "context", []map[string]string{
		{"id": "1", "title": "before"},
		{"id": "2", "title": "BLUE Lamp"},
		{"id": "3", "title": "after"},
		{"id": "4", "title": "blue chair"},
	})
	if err != nil {
		t.Fatal(err)
	}
	matches, err := cache.Grep("marketplace", GrepOptions{Pattern: `blue (lamp|chair)`, Insensitive: true, Context: 1, MaxMatches: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || len(matches[0].Before) != 1 || len(matches[0].After) != 1 {
		t.Fatalf("matches=%#v", matches)
	}
	for _, options := range []GrepOptions{
		{Pattern: "[", MaxMatches: 1},
		{Pattern: "x", Context: 6, MaxMatches: 1},
		{Pattern: "x", MaxMatches: 101},
	} {
		if _, err := cache.Grep("marketplace", options); err == nil {
			t.Fatalf("invalid grep options admitted: %#v", options)
		}
	}
}

func TestDefaultCacheRootAndScopeRejectSymlinkDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	root, err := DefaultCacheRoot()
	if err != nil || !strings.Contains(root, "browser-site-cache") {
		t.Fatalf("root=%q err=%v", root, err)
	}
	actual := t.TempDir()
	linked := filepath.Join(t.TempDir(), "linked-cache")
	if err := os.Symlink(actual, linked); err != nil {
		t.Fatal(err)
	}
	_, err = (Cache{Root: linked}).Write("marketplace", "query", nil)
	if ErrorCode(err) != "CACHE_SCOPE_REFUSED" {
		t.Fatalf("symlink root error=%v", err)
	}
}

func TestDefaultCacheScopeRejectsSymlinkedMacInfraAncestor(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	external := t.TempDir()
	externalSite := filepath.Join(external, "mac-infra", "browser-site-cache", "marketplace")
	if err := os.MkdirAll(externalSite, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(externalSite, "outside.jsonl"), []byte(`{"title":"outside marker"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	applicationSupport := filepath.Join(home, "Library", "Application Support")
	if err := os.MkdirAll(applicationSupport, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(external, "mac-infra"), filepath.Join(applicationSupport, "mac-infra")); err != nil {
		t.Fatal(err)
	}
	_, err := (Cache{}).Grep("marketplace", GrepOptions{Pattern: "outside", MaxMatches: 10})
	if ErrorCode(err) != "CACHE_SCOPE_REFUSED" {
		t.Fatalf("symlinked ancestor error=%v", err)
	}
}
