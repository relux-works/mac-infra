package browserfacade

import (
	"encoding/json"
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
