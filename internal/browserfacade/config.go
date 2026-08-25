package browserfacade

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/relux-works/mac-infra/internal/browserquery"
	"github.com/relux-works/mac-infra/internal/browsersession"
)

const (
	maximumPages       = 20
	maximumSettleMS    = 5000
	maximumStatements  = 16
	maximumQueryLength = 16384
)

var safeNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)

type Adapter struct {
	Name       string                 `json:"name"`
	Browser    browsersession.Browser `json:"browser"`
	Target     browsersession.Target  `json:"target"`
	Template   browserquery.Template  `json:"template"`
	Pagination Pagination             `json:"pagination"`
	Mutations  map[string]Mutation    `json:"mutations,omitempty"`
}

type Pagination struct {
	Kind               string `json:"kind"`
	Selector           string `json:"selector,omitempty"`
	ContainerSelector  string `json:"containerSelector,omitempty"`
	MaxPages           int    `json:"maxPages"`
	SettleMilliseconds int    `json:"settleMilliseconds,omitempty"`
}

type Mutation struct {
	Description string `json:"description"`
	Selector    string `json:"selector"`
	Destructive bool   `json:"destructive"`
}

func DecodeAdapter(data []byte) (Adapter, error) {
	decision, boundaryErr := EnforceOutbound(string(data))
	if boundaryErr != nil {
		return Adapter{}, boundaryErr
	}
	if decision.State != OutboundClean || decision.Value != string(data) {
		return Adapter{}, coded("SENSITIVE_RESPONSE_REFUSED", "adapter metadata was not clean at the outbound boundary")
	}
	var adapter Adapter
	decoder := json.NewDecoder(strings.NewReader(decision.Value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&adapter); err != nil {
		return Adapter{}, coded("ADAPTER_INVALID", "decode adapter: %v", err)
	}
	if err := adapter.Validate(); err != nil {
		return Adapter{}, err
	}
	return adapter, nil
}

func (a Adapter) Validate() error {
	if !safeNamePattern.MatchString(a.Name) {
		return coded("ADAPTER_INVALID", "adapter name must match %s", safeNamePattern)
	}
	if a.Target.Browser != "" && a.Target.Browser != a.Browser {
		return coded("ADAPTER_INVALID", "target browser must be empty or match adapter browser")
	}
	switch a.Browser {
	case browsersession.BrowserChrome:
		if strings.TrimSpace(a.Target.TabID) == "" {
			return coded("ADAPTER_INVALID", "Chrome adapter requires an exact tabId")
		}
	case browsersession.BrowserSafari:
		if strings.TrimSpace(a.Target.TabID) != "" {
			return coded("ADAPTER_INVALID", "Safari adapter is exact-window/current-tab and must not define tabId")
		}
	default:
		return coded("ADAPTER_INVALID", "browser must be chrome or safari")
	}
	if strings.TrimSpace(a.Target.WindowID) == "" {
		return coded("ADAPTER_INVALID", "adapter requires an exact windowId")
	}
	if err := validateOrigin(a.Target.Origin); err != nil {
		return err
	}
	if err := a.Template.Validate(); err != nil {
		return coded("ADAPTER_INVALID", "template: %v", err)
	}
	for name := range a.Template.Fields {
		if !safePublicField(name) {
			return coded("SENSITIVE_FIELD_REFUSED", "template field %q could carry browser session material", name)
		}
	}
	if err := a.Pagination.validate(); err != nil {
		return err
	}
	for name, mutation := range a.Mutations {
		if !safeNamePattern.MatchString(name) {
			return coded("ADAPTER_INVALID", "mutation name %q is invalid", name)
		}
		if strings.TrimSpace(mutation.Description) == "" || len(mutation.Description) > 240 {
			return coded("ADAPTER_INVALID", "mutation %q description must contain 1..240 characters", name)
		}
		decision, err := EnforceOutbound(mutation.Description)
		if err != nil || decision.State != OutboundClean {
			return coded("SENSITIVE_RESPONSE_REFUSED", "mutation %q description contains sensitive material", name)
		}
		if err := validateSelector("mutation "+name, mutation.Selector, false); err != nil {
			return err
		}
	}
	return nil
}

func validateOrigin(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return coded("ADAPTER_INVALID", "target origin must be an absolute http(s) origin")
	}
	if parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.String() != strings.TrimSpace(raw) {
		return coded("SECRET_BEARING_URL_REFUSED", "target origin must not contain credentials, path, query, or fragment")
	}
	return nil
}

func (p Pagination) validate() error {
	if p.MaxPages < 1 || p.MaxPages > maximumPages {
		return coded("PAGINATION_BOUND_INVALID", "pagination maxPages must be between 1 and %d", maximumPages)
	}
	if p.SettleMilliseconds < 0 || p.SettleMilliseconds > maximumSettleMS {
		return coded("PAGINATION_BOUND_INVALID", "settleMilliseconds must be between 0 and %d", maximumSettleMS)
	}
	switch p.Kind {
	case "none":
		if p.MaxPages != 1 || p.Selector != "" || p.ContainerSelector != "" {
			return coded("ADAPTER_INVALID", "none pagination requires maxPages=1 and no selectors")
		}
	case "next-page", "cursor":
		if err := validateSelector("pagination", p.Selector, false); err != nil {
			return err
		}
		if p.ContainerSelector != "" {
			return coded("ADAPTER_INVALID", "%s pagination must not define containerSelector", p.Kind)
		}
	case "infinite-scroll":
		if p.Selector != "" {
			return coded("ADAPTER_INVALID", "infinite-scroll pagination must not define selector")
		}
		if err := validateSelector("pagination container", p.ContainerSelector, true); err != nil {
			return err
		}
	default:
		return coded("ADAPTER_INVALID", "pagination kind must be none, next-page, cursor, or infinite-scroll")
	}
	return nil
}

func validateSelector(label, selector string, optional bool) error {
	trimmed := strings.TrimSpace(selector)
	if trimmed == "" {
		if optional {
			return nil
		}
		return coded("ADAPTER_INVALID", "%s selector is required", label)
	}
	if len(trimmed) > 512 || strings.ContainsAny(trimmed, "\r\n") {
		return coded("ADAPTER_INVALID", "%s selector must be one line with at most 512 characters", label)
	}
	if err := browsersession.GuardJavaScript(trimmed); err != nil {
		return coded("SENSITIVE_SELECTOR_REFUSED", "%s selector contains forbidden browser-session material", label)
	}
	return nil
}

func sortedFields(template browserquery.Template) []string {
	fields := make([]string, 0, len(template.Fields))
	for name := range template.Fields {
		fields = append(fields, name)
	}
	sort.Strings(fields)
	return fields
}

type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

func (e *Error) ErrorCode() string { return e.Code }

func coded(code, format string, args ...any) error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

func ErrorCode(err error) string {
	var typed interface{ ErrorCode() string }
	if errors.As(err, &typed) {
		return typed.ErrorCode()
	}
	return "INTERNAL_ERROR"
}
