package browserfacade

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/browsersession"
)

func TestDecodeAdapterAcceptsEveryExplicitPaginationContract(t *testing.T) {
	for _, kind := range []string{"none", "next-page", "cursor", "infinite-scroll"} {
		t.Run(kind, func(t *testing.T) {
			adapter := testAdapter(kind, 1)
			data, err := json.Marshal(adapter)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeAdapter(data)
			if err != nil || decoded.Pagination.Kind != kind {
				t.Fatalf("decoded=%#v err=%v", decoded, err)
			}
		})
	}
}

func TestDecodeAdapterRejectsDuplicateAndEscapedSensitiveMetadataBeforeLossyDecode(t *testing.T) {
	duplicate := []byte(`{"name":"marketplace","name":"shadow","browser":"chrome","target":{"browser":"chrome","windowId":"11","tabId":"22","origin":"https://shop.example"},"template":{"itemSelector":".item","fields":{"id":{"source":"text"}}},"pagination":{"kind":"none","maxPages":1}}`)
	if _, err := DecodeAdapter(duplicate); ErrorCode(err) != "SENSITIVE_RESPONSE_UNKNOWN" {
		t.Fatalf("duplicate adapter keys were not rejected by the outbound owner: %v", err)
	}

	adapter := testAdapter("none", 1)
	adapter.Mutations = map[string]Mutation{}
	adapter.Mutations["install"] = Mutation{Description: `Visit https:\/\/shop.example\/action?session_id=escaped-session-value`, Selector: "button.install"}
	data, err := json.Marshal(adapter)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAdapter(data); ErrorCode(err) != "SENSITIVE_RESPONSE_REFUSED" {
		t.Fatalf("escaped secret metadata was not rejected by the outbound owner: %v", err)
	}
}

func TestAdapterValidationRefusesTargetAndPaginationAmbiguity(t *testing.T) {
	cases := map[string]func(Adapter) Adapter{
		"browser":         func(a Adapter) Adapter { a.Browser = "firefox"; return a },
		"target-mismatch": func(a Adapter) Adapter { a.Target.Browser = browsersession.BrowserSafari; return a },
		"missing-window":  func(a Adapter) Adapter { a.Target.WindowID = ""; return a },
		"safari-tab": func(a Adapter) Adapter {
			a.Browser = browsersession.BrowserSafari
			a.Target.Browser = browsersession.BrowserSafari
			return a
		},
		"missing-pages":  func(a Adapter) Adapter { a.Pagination.MaxPages = 0; return a },
		"too-many-pages": func(a Adapter) Adapter { a.Pagination.MaxPages = 21; return a },
		"unknown-kind":   func(a Adapter) Adapter { a.Pagination.Kind = "api"; return a },
		"none-selector":  func(a Adapter) Adapter { a.Pagination.Selector = ".next"; return a },
		"infinite-trigger": func(a Adapter) Adapter {
			a.Pagination.Kind = "infinite-scroll"
			a.Pagination.Selector = ".next"
			return a
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if err := mutate(testAdapter("none", 1)).Validate(); err == nil {
				t.Fatal("ambiguous adapter admitted")
			}
		})
	}
	if _, err := DecodeAdapter([]byte(`{"unknown":true}`)); ErrorCode(err) != "ADAPTER_INVALID" {
		t.Fatalf("decode error=%v", err)
	}
}

// Bug (2026-10-21): an adapter whose itemSelector is a CSS attribute selector
// decodes; before the fix every command, schema() included, refused with
// SENSITIVE_RESPONSE_UNKNOWN. A secret-bearing attribute selector is refused.
func TestDecodeAdapterAcceptsAttributeSelector(t *testing.T) {
	adapter := testAdapter("next-page", 1)
	adapter.Template.ItemSelector = `[data-widget="searchResults"] > div`
	data, err := json.Marshal(adapter)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAdapter(data); err != nil {
		t.Fatalf("attribute selector adapter refused: %v", err)
	}
	adapter.Template.ItemSelector = `[data-token="abcdefgh12345"] > div`
	data, _ = json.Marshal(adapter)
	if _, err := DecodeAdapter(data); err == nil {
		t.Fatal("secret-bearing attribute selector admitted")
	}
}

// The mutation-name refusal names the required pattern, so an adapter author
// can fix a camelCase name such as openCart; a kebab-case name is accepted.
func TestDecodeAdapterMutationNameMessage(t *testing.T) {
	adapter := testAdapter("next-page", 1)
	adapter.Mutations = map[string]Mutation{"openCart": {Description: "open the cart", Selector: "a.cart"}}
	data, _ := json.Marshal(adapter)
	_, err := DecodeAdapter(data)
	if err == nil || !strings.Contains(err.Error(), "^[a-z][a-z0-9-]{0,47}$") || !strings.Contains(err.Error(), "open-cart") {
		t.Fatalf("mutation name error lacks the pattern: %v", err)
	}
	adapter.Mutations = map[string]Mutation{"open-cart": {Description: "open the cart", Selector: "a.cart"}}
	data, _ = json.Marshal(adapter)
	if _, err := DecodeAdapter(data); err != nil {
		t.Fatalf("kebab-case mutation refused: %v", err)
	}
}

// Review F4 (PR #29): a mutation description that hides a credential inside a
// harmless assignment is refused by DecodeAdapter, so schema() cannot emit it.
func TestDecodeAdapterRefusesNestedCredentialInDescription(t *testing.T) {
	adapter := testAdapter("next-page", 1)
	adapter.Mutations = map[string]Mutation{"open-cart": {Description: "note 'title': 'cookie=abcdefgh12345'", Selector: "a.cart"}}
	data, _ := json.Marshal(adapter)
	if _, err := DecodeAdapter(data); err == nil {
		t.Fatal("credential in a mutation description admitted")
	}
}

// Review F8 (PR #29): a Kelvin-sign cookie name in a mutation description is
// refused by DecodeAdapter, so schema() cannot emit it.
func TestDecodeAdapterRefusesFoldedCredentialName(t *testing.T) {
	adapter := testAdapter("next-page", 1)
	adapter.Mutations = map[string]Mutation{"open-cart": {Description: "coo\u212aie=abcdefgh12345", Selector: "a.cart"}}
	data, _ := json.Marshal(adapter)
	if _, err := DecodeAdapter(data); err == nil {
		t.Fatal("folded credential name in a mutation description admitted")
	}
}

// Review F9 (PR #29): 0Key (Kelvin sign) in a mutation description is refused
// by DecodeAdapter, so schema() cannot emit the value.
func TestDecodeAdapterRefusesRawBoundaryFoldedName(t *testing.T) {
	adapter := testAdapter("next-page", 1)
	adapter.Mutations = map[string]Mutation{"open-cart": {Description: "0\u212aey=abcdefgh12345", Selector: "a.cart"}}
	data, _ := json.Marshal(adapter)
	if _, err := DecodeAdapter(data); err == nil {
		t.Fatal("0Key credential in a mutation description admitted")
	}
}
