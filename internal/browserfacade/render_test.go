package browserfacade

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderJSONAndCompactContracts(t *testing.T) {
	list := ListResult{Items: []map[string]string{{"id": "1", "title": "Lamp"}}, Returned: 1, PagesRead: 1, Scanned: 1, HasMore: "false", CacheFile: "query.jsonl"}
	for _, format := range []string{"json", "compact"} {
		var output bytes.Buffer
		if err := RenderQuery(&output, []any{list}, format); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), "Lamp") {
			t.Fatalf("format=%s output=%s", format, output.String())
		}
	}
	mutations := []MutationResult{{OK: true, Mutation: "install", Preview: true, RequiresConfirm: true, Verification: "not-run"}}
	for _, format := range []string{"json", "compact"} {
		var output bytes.Buffer
		if err := RenderMutations(&output, mutations, format); err != nil || !strings.Contains(output.String(), "install") {
			t.Fatalf("format=%s output=%s err=%v", format, output.String(), err)
		}
	}
	matches := []GrepMatch{{File: "query.jsonl", Line: 2, Text: "match", Before: []string{"before"}, After: []string{"after"}}}
	for _, format := range []string{"json", "compact"} {
		var output bytes.Buffer
		if err := RenderGrep(&output, matches, format); err != nil || !strings.Contains(output.String(), "match") {
			t.Fatalf("format=%s output=%s err=%v", format, output.String(), err)
		}
	}
	for _, render := range []func(*bytes.Buffer) error{
		func(output *bytes.Buffer) error { return RenderQuery(output, []any{list}, "yaml") },
		func(output *bytes.Buffer) error { return RenderMutations(output, mutations, "yaml") },
		func(output *bytes.Buffer) error { return RenderGrep(output, matches, "yaml") },
	} {
		var output bytes.Buffer
		if err := render(&output); ErrorCode(err) != "FORMAT_INVALID" {
			t.Fatalf("format refusal err=%v", err)
		}
	}
}

func TestRenderGrepAcceptsCanonicalRedactedCacheRecords(t *testing.T) {
	record := `{"id":"p-1","url":"https://shop.example/item?cookie=%5Bredacted%5D&localStorage=%5Bredacted%5D&session_id=%5Bredacted%5D"}`
	for _, format := range []string{"compact", "json"} {
		var output bytes.Buffer
		matches := []GrepMatch{{File: "query-safe.jsonl", Line: 1, Text: record}}
		err := RenderGrep(&output, matches, format)
		if err != nil || !strings.Contains(output.String(), "redacted") {
			t.Fatalf("format=%s output=%s err=%v", format, output.String(), err)
		}
	}
}

func TestEveryRendererAppliesCentralOutboundBoundary(t *testing.T) {
	for name, render := range map[string]func(*bytes.Buffer) error{
		"query-json": func(output *bytes.Buffer) error {
			return RenderQuery(output, []any{ListResult{Items: []map[string]string{{"title": "glpat-0123456789abcdefghijklmnop"}}}}, "json")
		},
		"query-compact": func(output *bytes.Buffer) error {
			return RenderQuery(output, []any{ListResult{Items: []map[string]string{{"title": "glpat-0123456789abcdefghijklmnop"}}}}, "compact")
		},
		"grep-json": func(output *bytes.Buffer) error {
			return RenderGrep(output, []GrepMatch{{File: "query.jsonl", Line: 1, Text: "Bearer renderer-secret"}}, "json")
		},
		"grep-compact": func(output *bytes.Buffer) error {
			return RenderGrep(output, []GrepMatch{{File: "query.jsonl", Line: 1, Text: "Bearer renderer-secret"}}, "compact")
		},
		"mutation-json": func(output *bytes.Buffer) error {
			return RenderMutations(output, []MutationResult{{OK: true, Mutation: "glpat-0123456789abcdefghijklmnop"}}, "json")
		},
		"mutation-compact": func(output *bytes.Buffer) error {
			return RenderMutations(output, []MutationResult{{OK: true, Mutation: "glpat-0123456789abcdefghijklmnop"}}, "compact")
		},
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			err := render(&output)
			if ErrorCode(err) != "SENSITIVE_RESPONSE_REFUSED" || output.Len() != 0 {
				t.Fatalf("renderer bypass err=%v output=%s", err, output.String())
			}
		})
	}
}
