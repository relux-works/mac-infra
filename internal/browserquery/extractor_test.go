package browserquery

import (
	"strings"
	"testing"
)

func TestBuildJavaScriptIsBoundedAndDeterministic(t *testing.T) {
	template := Template{ItemSelector: "conversation-ui-message", PierceShadowRoots: true, Fields: map[string]Field{"tag": {Source: "tag"}, "text": {Source: "text"}}}
	source, err := BuildJavaScript(template, Query{Fields: []string{"tag", "text"}, Skip: 2, Take: 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"querySelectorAll", "shadowRoot", "roots.length < 64", "tagName.toLowerCase", "slice(spec.query.skip", `"take":20`, `"maxFieldChars":2000`} {
		if !strings.Contains(source, want) {
			t.Fatalf("extractor missing %q", want)
		}
	}
	for _, forbidden := range []string{"document.cookie", "localStorage", "sessionStorage", "location.href"} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("extractor contains forbidden token %q", forbidden)
		}
	}
}

func TestExtractorRejectsUnboundedAndSensitiveShapes(t *testing.T) {
	badAttribute := Template{ItemSelector: ".item", Fields: map[string]Field{"url": {Source: "attribute", Attribute: "href"}}}
	if _, err := BuildJavaScript(badAttribute, Query{Take: 1}); err == nil {
		t.Fatal("href extraction accepted")
	}
	template := Template{ItemSelector: ".item", Fields: map[string]Field{"text": {Source: "text"}}}
	if _, err := BuildJavaScript(template, Query{Take: 101}); err == nil {
		t.Fatal("unbounded take accepted")
	}
}

func TestPredicateMustReferenceKnownField(t *testing.T) {
	template := Template{ItemSelector: ".item", Fields: map[string]Field{"text": {Source: "text"}}}
	_, err := BuildJavaScript(template, Query{Take: 10, Predicate: &Predicate{Field: "missing", Op: "contains", Value: "x"}})
	if err == nil || !strings.Contains(err.Error(), "unknown predicate field") {
		t.Fatalf("error = %v", err)
	}
}
