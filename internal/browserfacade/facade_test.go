package browserfacade

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/browserquery"
	"github.com/relux-works/mac-infra/internal/browsersession"
)

type fakeTransport struct {
	extracts     []ExtractResponse
	evaluations  []string
	extractCalls []browserquery.Query
	evalSources  []string
}

func (f *fakeTransport) Extract(_ context.Context, _ Adapter, query browserquery.Query) (ExtractResponse, error) {
	f.extractCalls = append(f.extractCalls, query)
	if len(f.extracts) == 0 {
		return ExtractResponse{}, errors.New("unexpected extract")
	}
	response := f.extracts[0]
	f.extracts = f.extracts[1:]
	response.Skip = query.Skip
	response.Take = query.Take
	response.Returned = len(response.Items)
	return response, nil
}

func (f *fakeTransport) Evaluate(_ context.Context, _ Adapter, source string) (string, error) {
	f.evalSources = append(f.evalSources, source)
	if len(f.evaluations) == 0 {
		return "", errors.New("unexpected evaluate")
	}
	response := f.evaluations[0]
	f.evaluations = f.evaluations[1:]
	return response, nil
}

func TestQuerySupportsSchemaProjectionBatchingAndCompactOutput(t *testing.T) {
	adapter := testAdapter("none", 1)
	transport := &fakeTransport{extracts: []ExtractResponse{{Matched: 1, Items: []map[string]any{{"id": "p-1", "title": "Lamp", "price": "$20", "url": "https://shop.example/p/1"}}}}}
	facade := Facade{Transport: transport, Cache: Cache{Root: t.TempDir()}}
	results, err := facade.Query(context.Background(), adapter, `schema(); list(take=1) { id title }`)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results=%d", len(results))
	}
	list := results[1].(ListResult)
	if got := list.Items[0]; got["id"] != "p-1" || got["title"] != "Lamp" || got["price"] != "" {
		t.Fatalf("projection escaped: %#v", got)
	}
	if got := transport.extractCalls[0].Fields; strings.Join(got, ",") != "id,title" {
		t.Fatalf("extract fields=%v", got)
	}
	var compact bytes.Buffer
	if err := RenderQuery(&compact, results, "compact"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"operations"`, "id,title", "p-1,Lamp", "# returned=1"} {
		if !strings.Contains(compact.String(), want) {
			t.Fatalf("compact output missing %q:\n%s", want, compact.String())
		}
	}
}

func TestListProductionLogicPaginatesPastRenderedDOMWithinDeclaredBound(t *testing.T) {
	adapter := testAdapter("next-page", 3)
	transport := &fakeTransport{
		extracts: []ExtractResponse{
			{Matched: 2, Items: []map[string]any{{"id": "1", "title": "one"}, {"id": "2", "title": "two"}}},
			{Matched: 2, Items: []map[string]any{{"id": "3", "title": "three"}, {"id": "4", "title": "four"}}},
		},
		evaluations: []string{`{"advanced":true}`},
	}
	facade := Facade{Transport: transport, Cache: Cache{Root: t.TempDir()}}
	results, err := facade.Query(context.Background(), adapter, `list(skip=1,take=3,max_pages=2) { id title }`)
	if err != nil {
		t.Fatal(err)
	}
	list := results[0].(ListResult)
	if list.PagesRead != 2 || list.Returned != 3 || list.Items[0]["id"] != "2" || list.Items[2]["id"] != "4" {
		t.Fatalf("list=%#v", list)
	}
	if len(transport.extractCalls) != 2 || len(transport.evalSources) != 1 {
		t.Fatalf("extracts=%d advances=%d", len(transport.extractCalls), len(transport.evalSources))
	}
}

func TestSinglePageListReportsProvenExhaustionAndKnownAdditionalItems(t *testing.T) {
	adapter := testAdapter("none", 1)
	cases := map[string]struct {
		take int
		more string
	}{"all": {2, "false"}, "subset": {1, "true"}}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			transport := &fakeTransport{extracts: []ExtractResponse{{Matched: 2, Items: []map[string]any{{"id": "1", "title": "one"}, {"id": "2", "title": "two"}}}}}
			results, err := (Facade{Transport: transport, Cache: Cache{Root: t.TempDir()}}).Query(context.Background(), adapter, fmt.Sprintf(`list(take=%d) { id }`, testCase.take))
			if err != nil {
				t.Fatal(err)
			}
			if got := results[0].(ListResult).HasMore; got != testCase.more {
				t.Fatalf("hasMore=%s want=%s", got, testCase.more)
			}
		})
	}
}

func TestListNarrowsPaginationAtRequestedMaxPages(t *testing.T) {
	adapter := testAdapter("next-page", 3)
	transport := &fakeTransport{
		extracts: []ExtractResponse{
			{Matched: 1, Items: []map[string]any{{"id": "1", "title": "one"}}},
			{Matched: 1, Items: []map[string]any{{"id": "2", "title": "two"}}},
		},
		evaluations: []string{`{"advanced":true}`},
	}
	facade := Facade{Transport: transport, Cache: Cache{Root: t.TempDir()}}
	results, err := facade.Query(context.Background(), adapter, `list(take=10,max_pages=2) { id }`)
	if err != nil {
		t.Fatal(err)
	}
	list := results[0].(ListResult)
	if list.PagesRead != 2 || list.HasMore != "unknown" || len(transport.extractCalls) != 2 || len(transport.evalSources) != 1 {
		t.Fatalf("bound not enforced: list=%#v extracts=%d advances=%d", list, len(transport.extractCalls), len(transport.evalSources))
	}
}

func TestListReportsUnknownForDuplicatePageAndAdapterBound(t *testing.T) {
	for name, query := range map[string]string{
		"duplicate-page": `list(take=10,max_pages=3) { id }`,
		"adapter-bound":  `list(take=10) { id }`,
	} {
		t.Run(name, func(t *testing.T) {
			adapter := testAdapter("next-page", 2)
			second := map[string]any{"id": "2", "title": "two"}
			if name == "duplicate-page" {
				adapter.Pagination.MaxPages = 3
				second = map[string]any{"id": "1", "title": "one"}
			}
			transport := &fakeTransport{
				extracts: []ExtractResponse{
					{Matched: 1, Items: []map[string]any{{"id": "1", "title": "one"}}},
					{Matched: 1, Items: []map[string]any{second}},
				},
				evaluations: []string{`{"advanced":true}`},
			}
			results, err := (Facade{Transport: transport, Cache: Cache{Root: t.TempDir()}}).Query(context.Background(), adapter, query)
			if err != nil {
				t.Fatal(err)
			}
			if got := results[0].(ListResult).HasMore; got != "unknown" {
				t.Fatalf("hasMore=%s, want unknown", got)
			}
		})
	}
}

func TestListReportsUnknownAtGlobalScanBound(t *testing.T) {
	adapter := testAdapter("next-page", 20)
	transport := &fakeTransport{}
	for page := 0; page < 10; page++ {
		items := make([]map[string]any, 0, 100)
		for item := 0; item < 100; item++ {
			items = append(items, map[string]any{"id": fmt.Sprintf("%d-%d", page, item)})
		}
		transport.extracts = append(transport.extracts, ExtractResponse{Matched: 100, Items: items})
		if page < 9 {
			transport.evaluations = append(transport.evaluations, `{"advanced":true}`)
		}
	}
	results, err := (Facade{Transport: transport, Cache: Cache{Root: t.TempDir()}}).Query(context.Background(), adapter, `list(skip=900,take=100) { id }`)
	if err != nil {
		t.Fatal(err)
	}
	list := results[0].(ListResult)
	if list.Scanned != maximumScannedItems || list.HasMore != "unknown" {
		t.Fatalf("list=%#v", list)
	}
}

func TestPaginationDistinguishesExplicitExhaustionFromPartialAdvanceRead(t *testing.T) {
	adapter := testAdapter("next-page", 2)
	for name, response := range map[string]string{
		"explicit-exhaustion": `{"advanced":false}`,
		"partial-read":        `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			transport := &fakeTransport{
				extracts:    []ExtractResponse{{Matched: 1, Items: []map[string]any{{"id": "1"}}}},
				evaluations: []string{response},
			}
			results, err := (Facade{Transport: transport, Cache: Cache{Root: t.TempDir()}}).Query(context.Background(), adapter, `list(take=10) { id }`)
			if name == "partial-read" {
				if ErrorCode(err) != "TRANSPORT_RESPONSE_INVALID" {
					t.Fatalf("error=%v code=%s", err, ErrorCode(err))
				}
				return
			}
			if err != nil || results[0].(ListResult).HasMore != "false" {
				t.Fatalf("results=%#v err=%v", results, err)
			}
		})
	}
}

func TestCursorAndInfiniteScrollAdvanceContractsDoNotExposeCursorState(t *testing.T) {
	cursor, err := advanceJavaScript(Pagination{Kind: "cursor", Selector: "button.more", MaxPages: 2})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"dataset", "cursor", "location", "fetch("} {
		if strings.Contains(strings.ToLower(cursor), forbidden) {
			t.Fatalf("cursor adapter exposed %q: %s", forbidden, cursor)
		}
	}
	infinite, err := advanceJavaScript(Pagination{Kind: "infinite-scroll", ContainerSelector: ".results", MaxPages: 2})
	if err != nil || !strings.Contains(infinite, "scrollTo") || !strings.Contains(infinite, "advanced:") {
		t.Fatalf("infinite-scroll source=%q err=%v", infinite, err)
	}
}

func TestAdapterRejectsSecretBearingURLsFieldsAndSelectors(t *testing.T) {
	cases := map[string]func(Adapter) Adapter{
		"url-query":    func(a Adapter) Adapter { a.Target.Origin += "?token=secret"; return a },
		"url-fragment": func(a Adapter) Adapter { a.Target.Origin += "#opaque"; return a },
		"auth-field": func(a Adapter) Adapter {
			a.Template.Fields["authorization"] = browserquery.Field{Source: "text"}
			return a
		},
		"storage-field": func(a Adapter) Adapter {
			a.Template.Fields["localStorage"] = browserquery.Field{Source: "text"}
			return a
		},
		"cookie-field":    func(a Adapter) Adapter { a.Template.Fields["cookie"] = browserquery.Field{Source: "text"}; return a },
		"opaque-state":    func(a Adapter) Adapter { a.Template.Fields["state"] = browserquery.Field{Source: "text"}; return a },
		"api-key":         func(a Adapter) Adapter { a.Template.Fields["apiKey"] = browserquery.Field{Source: "text"}; return a },
		"csrf":            func(a Adapter) Adapter { a.Template.Fields["csrfToken"] = browserquery.Field{Source: "text"}; return a },
		"secret-selector": func(a Adapter) Adapter { a.Pagination.Selector = `[data-x="document.cookie"]`; return a },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			adapter := mutate(testAdapter("next-page", 2))
			if err := adapter.Validate(); err == nil {
				t.Fatalf("unsafe adapter admitted: %#v", adapter)
			}
		})
	}
}

func TestQueryRefusesAuthorizationOpaqueStateAndTokensBeforeCacheWrite(t *testing.T) {
	for name, item := range map[string]map[string]any{
		"authorization-value": {"id": "1", "title": "Authorization: Bearer abcdefghijklmnop"},
		"github-token":        {"id": "1", "title": "ghp_012345678901234567890123456789012345"},
		"opaque-state-key":    {"id": "1", "title": "safe", "sessionState": "opaque"},
		"jwt":                 {"id": "1", "title": "abcdefghijkl.abcdefghijkl.abcdefghijkl"},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			transport := &fakeTransport{extracts: []ExtractResponse{{Matched: 1, Items: []map[string]any{item}}}}
			_, err := (Facade{Transport: transport, Cache: Cache{Root: root}}).Query(context.Background(), testAdapter("none", 1), `list(take=1) { id title }`)
			if err == nil || ErrorCode(err) != "SENSITIVE_RESPONSE_REFUSED" {
				t.Fatalf("error=%v code=%s", err, ErrorCode(err))
			}
			entries, readErr := os.ReadDir(root)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("sensitive response reached cache: %v", entries)
			}
		})
	}
}

func TestQueryRedactsSecretBearingURLBeforeOutputAndCache(t *testing.T) {
	root := t.TempDir()
	transport := &fakeTransport{extracts: []ExtractResponse{{Matched: 1, Items: []map[string]any{{"id": "1", "title": "item", "url": "https://shop.example/item?code=topsecret&next=ok#opaque"}}}}}
	results, err := (Facade{Transport: transport, Cache: Cache{Root: root}}).Query(context.Background(), testAdapter("none", 1), `list(take=1) { id url }`)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(results)
	if bytes.Contains(data, []byte("topsecret")) || bytes.Contains(data, []byte("opaque")) || !bytes.Contains(data, []byte("redacted")) {
		t.Fatalf("unsafe output: %s", data)
	}
	cacheData, err := os.ReadFile(filepath.Join(root, "marketplace", results[0].(ListResult).CacheFile))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cacheData, []byte("topsecret")) || bytes.Contains(cacheData, []byte("opaque")) {
		t.Fatalf("unsafe cache: %s", cacheData)
	}
}

func TestMutationPreviewAndRefusalDoNotDispatchAndConfirmedBatchPrevalidates(t *testing.T) {
	adapter := testAdapter("none", 1)
	adapter.Mutations = map[string]Mutation{"install": {Description: "Install selected marketplace item", Selector: "button.install", Destructive: false}}
	transport := &fakeTransport{evaluations: []string{`{"applied":true,"verification":"unknown"}`}}
	facade := Facade{Transport: transport, Cache: Cache{Root: t.TempDir()}}
	preview, err := facade.Mutate(context.Background(), adapter, `invoke(name=install)`, true, false)
	if err != nil || !preview[0].Preview || len(transport.evalSources) != 0 {
		t.Fatalf("preview=%#v err=%v calls=%d", preview, err, len(transport.evalSources))
	}
	if _, err := facade.Mutate(context.Background(), adapter, `invoke(name=install)`, false, false); ErrorCode(err) != "CONFIRM_REQUIRED" || len(transport.evalSources) != 0 {
		t.Fatalf("confirm refusal err=%v calls=%d", err, len(transport.evalSources))
	}
	if _, err := facade.Mutate(context.Background(), adapter, `invoke(name=install); invoke(name=missing)`, false, true); ErrorCode(err) != "UNKNOWN_MUTATION" || len(transport.evalSources) != 0 {
		t.Fatalf("batch prevalidation err=%v calls=%d", err, len(transport.evalSources))
	}
	result, err := facade.Mutate(context.Background(), adapter, `invoke(name=install)`, false, true)
	if err != nil || !result[0].Applied || len(transport.evalSources) != 1 {
		t.Fatalf("result=%#v err=%v calls=%d", result, err, len(transport.evalSources))
	}
}

func TestParserPreservesQuotedSemicolonInsideBatchArgument(t *testing.T) {
	statements, err := Parse(`list(where_field=title,where_value="a;b") { id }; schema()`)
	if err != nil {
		t.Fatal(err)
	}
	if len(statements) != 2 || statements[0].Args["where_value"] != "a;b" {
		t.Fatalf("statements=%#v", statements)
	}
}

func TestPredicateUsesFoundationContractWhenPredicateFieldIsNotProjected(t *testing.T) {
	transport := &fakeTransport{extracts: []ExtractResponse{{Matched: 1, Items: []map[string]any{{"id": "1", "title": "Desk lamp"}}}}}
	results, err := (Facade{Transport: transport, Cache: Cache{Root: t.TempDir()}}).Query(context.Background(), testAdapter("none", 1), `list(take=1,where_field=title,where_op=contains,where_value=lamp) { id }`)
	if err != nil {
		t.Fatal(err)
	}
	if got := transport.extractCalls[0]; got.Predicate == nil || got.Predicate.Field != "title" || strings.Join(got.Fields, ",") != "id,title" {
		t.Fatalf("foundation query=%#v", got)
	}
	if item := results[0].(ListResult).Items[0]; len(item) != 1 || item["id"] != "1" {
		t.Fatalf("predicate support field escaped projection: %#v", item)
	}
}

func TestMutationRefusesDisabledTargetAndMalformedAttestation(t *testing.T) {
	adapter := testAdapter("none", 1)
	adapter.Mutations = map[string]Mutation{"install": {Description: "Install item", Selector: "button.install"}}
	for name, response := range map[string]string{
		"disabled":  `{"applied":false,"verification":"refused"}`,
		"malformed": `{"applied":true,"verification":"verified"}`,
	} {
		t.Run(name, func(t *testing.T) {
			transport := &fakeTransport{evaluations: []string{response}}
			_, err := (Facade{Transport: transport}).Mutate(context.Background(), adapter, `invoke(name=install)`, false, true)
			if name == "disabled" && ErrorCode(err) != "MUTATION_REFUSED" {
				t.Fatalf("error=%v", err)
			}
			if name == "malformed" && ErrorCode(err) != "TRANSPORT_RESPONSE_INVALID" {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestQueryAndParserRefuseUnknownOrMalformedShapesBeforeTransport(t *testing.T) {
	adapter := testAdapter("none", 1)
	transport := &fakeTransport{}
	facade := Facade{Transport: transport, Cache: Cache{Root: t.TempDir()}}
	queries := []string{
		`unknown()`,
		`schema(extra=yes)`,
		`list(take=101) { id }`,
		`list(where_field=title) { id }`,
		`list(where_field=title,where_value=x,where_op=regex) { id }`,
		`list() { missing }`,
		`list(extra=value) { id }`,
		`list(where_field=title,where_value="unterminated) { id }`,
	}
	for _, query := range queries {
		if _, err := facade.Query(context.Background(), adapter, query); err == nil {
			t.Fatalf("unsafe query admitted: %s", query)
		}
	}
	if len(transport.extractCalls) != 0 || len(transport.evalSources) != 0 {
		t.Fatalf("invalid query reached transport")
	}
}

func testAdapter(kind string, maxPages int) Adapter {
	pagination := Pagination{Kind: kind, MaxPages: maxPages}
	if kind == "next-page" || kind == "cursor" {
		pagination.Selector = "button.next"
	}
	if kind == "infinite-scroll" {
		pagination.ContainerSelector = ".results"
	}
	return Adapter{
		Name:    "marketplace",
		Browser: browsersession.BrowserChrome,
		Target:  browsersession.Target{Browser: browsersession.BrowserChrome, WindowID: "11", TabID: "22", Origin: "https://shop.example"},
		Template: browserquery.Template{ItemSelector: ".item", Fields: map[string]browserquery.Field{
			"id": {Source: "attribute", Attribute: "aria-label"}, "title": {Source: "text"}, "price": {Source: "text"}, "url": {Source: "text"},
		}},
		Pagination: pagination,
	}
}
