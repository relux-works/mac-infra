package browserfacade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/relux-works/mac-infra/internal/browserquery"
	"github.com/relux-works/mac-infra/internal/browsersession"
)

const maximumScannedItems = 1000

type CommandRunner interface {
	Run(ctx context.Context, command string, args ...string) (string, error)
}

type ExecRunner struct{}

type TransportFailure struct {
	Kind      string
	Command   string
	ExitClass string
}

func (e *TransportFailure) Error() string {
	return "browser transport failed; raw process detail was withheld"
}

func (e *TransportFailure) ErrorCode() string { return "TRANSPORT_FAILED" }

func (ExecRunner) Run(ctx context.Context, command string, args ...string) (string, error) {
	path, err := exec.LookPath(command)
	if err != nil {
		return "", coded("TRANSPORT_UNAVAILABLE", "%s is not installed", command)
	}
	cmd := exec.CommandContext(ctx, path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		exitClass := "process-exit"
		if _, boundaryErr := EnforceOutbound(detail); boundaryErr != nil {
			exitClass = "sensitive-or-indeterminate"
		}
		return "", &TransportFailure{Kind: "process", Command: command, ExitClass: exitClass}
	}
	return strings.TrimSpace(stdout.String()), nil
}

type Transport interface {
	Extract(context.Context, Adapter, browserquery.Query) (ExtractResponse, error)
	Evaluate(context.Context, Adapter, string) (string, error)
}

type CLITransport struct {
	Runner CommandRunner
}

type ExtractResponse struct {
	Matched  int              `json:"matched"`
	Skip     int              `json:"skip"`
	Take     int              `json:"take"`
	Returned int              `json:"returned"`
	Items    []map[string]any `json:"items"`
}

func (t CLITransport) Extract(ctx context.Context, adapter Adapter, query browserquery.Query) (ExtractResponse, error) {
	runner := t.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	var output string
	var err error
	switch adapter.Browser {
	case browsersession.BrowserChrome:
		templateData, marshalErr := json.Marshal(adapter.Template)
		if marshalErr != nil {
			return ExtractResponse{}, coded("INTERNAL_ERROR", "encode extraction template")
		}
		file, createErr := os.CreateTemp("", "mac-browser-site-template-*.json")
		if createErr != nil {
			return ExtractResponse{}, coded("CACHE_IO_FAILED", "create private extraction template: %v", createErr)
		}
		path := file.Name()
		defer os.Remove(path)
		if chmodErr := file.Chmod(0o600); chmodErr != nil {
			file.Close()
			return ExtractResponse{}, coded("CACHE_IO_FAILED", "protect extraction template: %v", chmodErr)
		}
		if _, writeErr := file.Write(templateData); writeErr != nil {
			file.Close()
			return ExtractResponse{}, coded("CACHE_IO_FAILED", "write extraction template: %v", writeErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			return ExtractResponse{}, coded("CACHE_IO_FAILED", "close extraction template: %v", closeErr)
		}
		args := []string{"extract", "--window-id", adapter.Target.WindowID, "--tab-id", adapter.Target.TabID, "--origin", adapter.Target.Origin, "--template", path, "--skip", strconv.Itoa(query.Skip), "--take", strconv.Itoa(query.Take)}
		if len(query.Fields) > 0 {
			args = append(args, "--fields", strings.Join(query.Fields, ","))
		}
		if query.Predicate != nil {
			args = append(args, "--where-field", query.Predicate.Field, "--where-op", query.Predicate.Op, "--where-value", query.Predicate.Value)
		}
		output, err = runner.Run(ctx, "mac-chrome-session", args...)
	case browsersession.BrowserSafari:
		source, buildErr := browserquery.BuildJavaScript(adapter.Template, query)
		if buildErr != nil {
			return ExtractResponse{}, coded("QUERY_INVALID", "%v", buildErr)
		}
		output, err = runner.Run(ctx, "mac-safari-session", "run-js", "--window-id", adapter.Target.WindowID, "--origin", adapter.Target.Origin, "--script", source)
	default:
		return ExtractResponse{}, coded("ADAPTER_INVALID", "unsupported browser transport")
	}
	if err != nil {
		return ExtractResponse{}, err
	}
	var wire struct {
		Matched  *int            `json:"matched"`
		Skip     *int            `json:"skip"`
		Take     *int            `json:"take"`
		Returned *int            `json:"returned"`
		Items    json.RawMessage `json:"items"`
	}
	if decodeErr := decodeOutboundSingleJSON(output, &wire); decodeErr != nil || wire.Matched == nil || wire.Skip == nil || wire.Take == nil || wire.Returned == nil || len(wire.Items) == 0 || string(wire.Items) == "null" {
		if decodeErr != nil && (ErrorCode(decodeErr) == "SENSITIVE_RESPONSE_REFUSED" || ErrorCode(decodeErr) == "SENSITIVE_RESPONSE_UNKNOWN") {
			return ExtractResponse{}, decodeErr
		}
		return ExtractResponse{}, coded("TRANSPORT_RESPONSE_INVALID", "browser extractor returned an unreadable response")
	}
	var items []map[string]any
	if decodeErr := json.Unmarshal(wire.Items, &items); decodeErr != nil || items == nil {
		return ExtractResponse{}, coded("TRANSPORT_RESPONSE_INVALID", "browser extractor returned an unreadable response")
	}
	response := ExtractResponse{Matched: *wire.Matched, Skip: *wire.Skip, Take: *wire.Take, Returned: *wire.Returned, Items: items}
	if response.Skip != query.Skip || response.Take != query.Take || response.Returned != len(response.Items) || response.Matched < response.Returned || response.Returned > query.Take {
		return ExtractResponse{}, coded("TRANSPORT_RESPONSE_INVALID", "browser extractor returned inconsistent bounds")
	}
	return response, nil
}

func (t CLITransport) Evaluate(ctx context.Context, adapter Adapter, source string) (string, error) {
	runner := t.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	args := []string{"run-js", "--window-id", adapter.Target.WindowID}
	command := "mac-safari-session"
	if adapter.Browser == browsersession.BrowserChrome {
		command = "mac-chrome-session"
		args = append(args, "--tab-id", adapter.Target.TabID)
	}
	args = append(args, "--origin", adapter.Target.Origin, "--script", source)
	return runner.Run(ctx, command, args...)
}

type Facade struct {
	Transport Transport
	Cache     Cache
	Sleep     func(time.Duration)
}

type ListResult struct {
	Items     []map[string]string `json:"items"`
	Skip      int                 `json:"skip"`
	Take      int                 `json:"take"`
	Returned  int                 `json:"returned"`
	PagesRead int                 `json:"pagesRead"`
	Scanned   int                 `json:"scanned"`
	HasMore   string              `json:"hasMore"`
	CacheFile string              `json:"cacheFile"`
}

type MutationResult struct {
	OK              bool   `json:"ok"`
	Mutation        string `json:"mutation"`
	Preview         bool   `json:"preview"`
	Destructive     bool   `json:"destructive"`
	RequiresConfirm bool   `json:"requiresConfirm"`
	Applied         bool   `json:"applied"`
	Verification    string `json:"verification"`
}

func (f Facade) Query(ctx context.Context, adapter Adapter, input string) ([]any, error) {
	if err := adapter.Validate(); err != nil {
		return nil, err
	}
	statements, err := Parse(input)
	if err != nil {
		return nil, err
	}
	results := make([]any, 0, len(statements))
	for _, statement := range statements {
		switch statement.Operation {
		case "schema":
			if len(statement.Fields) != 0 || len(statement.Args) != 0 {
				return nil, coded("QUERY_INVALID", "schema() accepts no arguments or projection")
			}
			results = append(results, schemaResult(adapter))
		case "list":
			result, executeErr := f.list(ctx, adapter, statement)
			if executeErr != nil {
				return nil, executeErr
			}
			results = append(results, result)
		default:
			return nil, coded("UNKNOWN_OPERATION", "unknown query operation %q; available operations: list, schema", statement.Operation)
		}
	}
	if err := enforceOutboundValue(results); err != nil {
		return nil, err
	}
	return results, nil
}

func (f Facade) list(ctx context.Context, adapter Adapter, statement Statement) (ListResult, error) {
	if err := requireOnlyArgs(statement, "skip", "take", "max_pages", "where_field", "where_op", "where_value"); err != nil {
		return ListResult{}, err
	}
	skip, err := intArg(statement.Args, "skip", 0, 0, maximumScannedItems-1)
	if err != nil {
		return ListResult{}, err
	}
	take, err := intArg(statement.Args, "take", 20, 1, 100)
	if err != nil {
		return ListResult{}, err
	}
	if skip+take > maximumScannedItems {
		return ListResult{}, coded("PAGINATION_BOUND_INVALID", "skip+take exceeds the %d item scan bound", maximumScannedItems)
	}
	maxPages, err := intArg(statement.Args, "max_pages", adapter.Pagination.MaxPages, 1, adapter.Pagination.MaxPages)
	if err != nil {
		return ListResult{}, err
	}
	fields := statement.Fields
	if len(fields) == 0 {
		fields = sortedFields(adapter.Template)
	}
	for _, field := range fields {
		if _, ok := adapter.Template.Fields[field]; !ok {
			return ListResult{}, coded("UNKNOWN_FIELD", "unknown projected field %q", field)
		}
		if !safePublicField(field) {
			return ListResult{}, coded("SENSITIVE_FIELD_REFUSED", "projected field %q is not public", field)
		}
	}
	predicate, err := predicateFrom(statement, adapter)
	if err != nil {
		return ListResult{}, err
	}
	extractFields := append([]string(nil), fields...)
	if predicate != nil && !contains(extractFields, predicate.Field) {
		extractFields = append(extractFields, predicate.Field)
		sort.Strings(extractFields)
	}
	if err := (browserquery.Query{Fields: extractFields, Predicate: predicate, Skip: 0, Take: 100}).Validate(adapter.Template); err != nil {
		return ListResult{}, coded("QUERY_INVALID", "%v", err)
	}
	transport := f.Transport
	if transport == nil {
		transport = CLITransport{}
	}
	var collected []map[string]string
	seenItems := map[string]bool{}
	seenPages := map[string]bool{}
	pagesRead, scanned := 0, 0
	hasMore := "unknown"
	for page := 0; page < maxPages && scanned < maximumScannedItems; page++ {
		pageItems := make([]map[string]string, 0)
		matched := 0
		for pageSkip := 0; scanned < maximumScannedItems; pageSkip += 100 {
			response, extractErr := transport.Extract(ctx, adapter, browserquery.Query{Fields: extractFields, Predicate: predicate, Skip: pageSkip, Take: min(100, maximumScannedItems-scanned)})
			if extractErr != nil {
				return ListResult{}, extractErr
			}
			matched = response.Matched
			sanitized, sanitizeErr := sanitizeItems(response.Items, fields)
			if sanitizeErr != nil {
				return ListResult{}, sanitizeErr
			}
			pageItems = append(pageItems, sanitized...)
			scanned += response.Returned
			if response.Returned == 0 || pageSkip+response.Returned >= response.Matched || response.Returned < response.Take {
				break
			}
		}
		pagesRead++
		pageDigest := digestItems(pageItems)
		if seenPages[pageDigest] {
			hasMore = "unknown"
			break
		}
		seenPages[pageDigest] = true
		for _, item := range pageItems {
			key := digestItem(item)
			if !seenItems[key] {
				seenItems[key] = true
				collected = append(collected, item)
			}
		}
		if len(collected) >= skip+take {
			if len(collected) > skip+take || adapter.Pagination.Kind == "none" {
				hasMore = strconv.FormatBool(len(collected) > skip+take)
			} else {
				hasMore = "unknown"
			}
			break
		}
		if matched > len(pageItems) {
			hasMore = "true"
			break
		}
		if scanned >= maximumScannedItems {
			hasMore = "unknown"
			break
		}
		if adapter.Pagination.Kind == "none" {
			hasMore = "false"
			break
		}
		if page+1 >= maxPages {
			hasMore = "unknown"
			break
		}
		advanced, advanceErr := f.advance(ctx, transport, adapter)
		if advanceErr != nil {
			return ListResult{}, advanceErr
		}
		if !advanced {
			hasMore = "false"
			break
		}
		if adapter.Pagination.SettleMilliseconds > 0 {
			sleep := f.Sleep
			if sleep == nil {
				sleep = time.Sleep
			}
			sleep(time.Duration(adapter.Pagination.SettleMilliseconds) * time.Millisecond)
		}
	}
	start := min(skip, len(collected))
	end := min(start+take, len(collected))
	items := append([]map[string]string(nil), collected[start:end]...)
	cacheFile, err := f.Cache.Write(adapter.Name, statementKey(statement), items)
	if err != nil {
		return ListResult{}, err
	}
	return ListResult{Items: items, Skip: skip, Take: take, Returned: len(items), PagesRead: pagesRead, Scanned: scanned, HasMore: hasMore, CacheFile: cacheFile}, nil
}

func predicateFrom(statement Statement, adapter Adapter) (*browserquery.Predicate, error) {
	field, hasField := statement.Args["where_field"]
	value, hasValue := statement.Args["where_value"]
	op, hasOp := statement.Args["where_op"]
	if !hasField && !hasValue && !hasOp {
		return nil, nil
	}
	if !hasField || !hasValue {
		return nil, coded("ARGUMENT_INVALID", "predicate requires where_field and where_value")
	}
	if _, ok := adapter.Template.Fields[field]; !ok || !safePublicField(field) {
		return nil, coded("UNKNOWN_FIELD", "predicate field %q is unavailable", field)
	}
	if !hasOp {
		op = "contains"
	}
	switch op {
	case "equals", "contains", "prefix":
	default:
		return nil, coded("ARGUMENT_INVALID", "where_op must be equals, contains, or prefix")
	}
	return &browserquery.Predicate{Field: field, Op: op, Value: value}, nil
}

func (f Facade) advance(ctx context.Context, transport Transport, adapter Adapter) (bool, error) {
	source, err := advanceJavaScript(adapter.Pagination)
	if err != nil {
		return false, err
	}
	output, err := transport.Evaluate(ctx, adapter, source)
	if err != nil {
		return false, err
	}
	var result struct {
		Advanced *bool `json:"advanced"`
	}
	if err := decodeOutboundSingleJSON(output, &result); err != nil || result.Advanced == nil {
		if err != nil && (ErrorCode(err) == "SENSITIVE_RESPONSE_REFUSED" || ErrorCode(err) == "SENSITIVE_RESPONSE_UNKNOWN") {
			return false, err
		}
		return false, coded("TRANSPORT_RESPONSE_INVALID", "pagination adapter returned an unreadable response")
	}
	return *result.Advanced, nil
}

func advanceJavaScript(pagination Pagination) (string, error) {
	selector, _ := json.Marshal(pagination.Selector)
	container, _ := json.Marshal(pagination.ContainerSelector)
	switch pagination.Kind {
	case "next-page", "cursor":
		// Cursor state deliberately remains owned by the site's click handler. It
		// is never read, returned, cached, or placed in a URL by this facade.
		return fmt.Sprintf(`(() => { const node=document.querySelector(%s); if(!node || node.disabled || node.getAttribute("aria-disabled")==="true") return JSON.stringify({advanced:false}); node.click(); return JSON.stringify({advanced:true}); })()`, selector), nil
	case "infinite-scroll":
		return fmt.Sprintf(`(() => { const node=%s ? document.querySelector(%s) : (document.scrollingElement || document.documentElement); if(!node) return JSON.stringify({advanced:false}); const before=Number(node.scrollTop||0); const target=Number(node.scrollHeight||0); if(target<=before+Number(node.clientHeight||0)) return JSON.stringify({advanced:false}); node.scrollTo(0,target); return JSON.stringify({advanced:Number(node.scrollTop||0)>before}); })()`, container, container), nil
	default:
		return "", coded("ADAPTER_INVALID", "pagination kind %q cannot advance", pagination.Kind)
	}
}

func (f Facade) Mutate(ctx context.Context, adapter Adapter, input string, dryRun, confirm bool) ([]MutationResult, error) {
	if err := adapter.Validate(); err != nil {
		return nil, err
	}
	statements, err := Parse(input)
	if err != nil {
		return nil, err
	}
	mutations := make([]struct {
		name string
		def  Mutation
	}, 0, len(statements))
	for _, statement := range statements {
		if statement.Operation != "invoke" {
			return nil, coded("UNKNOWN_MUTATION", "unknown mutation %q; available mutation: invoke", statement.Operation)
		}
		if len(statement.Fields) != 0 {
			return nil, coded("QUERY_INVALID", "mutations do not accept field projections")
		}
		if err := requireOnlyArgs(statement, "name"); err != nil {
			return nil, err
		}
		name := statement.Args["name"]
		definition, ok := adapter.Mutations[name]
		if !ok {
			return nil, coded("UNKNOWN_MUTATION", "adapter does not declare the requested mutation")
		}
		mutations = append(mutations, struct {
			name string
			def  Mutation
		}{name: name, def: definition})
	}
	if !dryRun && !confirm {
		return nil, coded("CONFIRM_REQUIRED", "browser mutations require explicit --confirm; use --dry-run for a no-write preview")
	}
	results := make([]MutationResult, 0, len(mutations))
	if dryRun {
		for _, mutation := range mutations {
			results = append(results, MutationResult{OK: true, Mutation: mutation.name, Preview: true, Destructive: mutation.def.Destructive, RequiresConfirm: true, Verification: "not-run"})
		}
		if err := enforceOutboundValue(results); err != nil {
			return nil, err
		}
		return results, nil
	}
	transport := f.Transport
	if transport == nil {
		transport = CLITransport{}
	}
	for _, mutation := range mutations {
		selector, _ := json.Marshal(mutation.def.Selector)
		source := fmt.Sprintf(`(() => { const node=document.querySelector(%s); if(!node || node.disabled || node.getAttribute("aria-disabled")==="true") return JSON.stringify({applied:false,verification:"refused"}); node.click(); return JSON.stringify({applied:true,verification:"unknown"}); })()`, selector)
		output, executeErr := transport.Evaluate(ctx, adapter, source)
		if executeErr != nil {
			return nil, executeErr
		}
		var response struct {
			Applied      bool   `json:"applied"`
			Verification string `json:"verification"`
		}
		if decodeErr := decodeOutboundSingleJSON(output, &response); decodeErr != nil || (response.Verification != "unknown" && response.Verification != "refused") {
			if decodeErr != nil && (ErrorCode(decodeErr) == "SENSITIVE_RESPONSE_REFUSED" || ErrorCode(decodeErr) == "SENSITIVE_RESPONSE_UNKNOWN") {
				return nil, decodeErr
			}
			return nil, coded("TRANSPORT_RESPONSE_INVALID", "mutation adapter returned an unreadable response")
		}
		if !response.Applied {
			return nil, coded("MUTATION_REFUSED", "mutation %q target is absent or disabled", mutation.name)
		}
		results = append(results, MutationResult{OK: true, Mutation: mutation.name, Destructive: mutation.def.Destructive, RequiresConfirm: true, Applied: true, Verification: response.Verification})
	}
	if err := enforceOutboundValue(results); err != nil {
		return nil, err
	}
	return results, nil
}

func schemaResult(adapter Adapter) map[string]any {
	mutations := make(map[string]any, len(adapter.Mutations))
	for name, mutation := range adapter.Mutations {
		mutations[name] = map[string]any{"description": mutation.Description, "destructive": mutation.Destructive, "requiresConfirm": true, "preview": true}
	}
	return map[string]any{
		"operations":    []string{"list", "schema"},
		"fields":        sortedFields(adapter.Template),
		"defaultFields": sortedFields(adapter.Template),
		"batching":      true,
		"formats":       []string{"compact", "json"},
		"pagination":    map[string]any{"kind": adapter.Pagination.Kind, "maxPages": adapter.Pagination.MaxPages, "maxTake": 100, "maxScannedItems": maximumScannedItems},
		"operationMetadata": map[string]any{
			"list":   map[string]any{"parameters": []string{"skip", "take", "max_pages", "where_field", "where_op", "where_value"}, "projection": true},
			"schema": map[string]any{"parameters": []string{}},
		},
		"mutations":        []string{"invoke"},
		"mutationMetadata": mutations,
		"grep":             map[string]any{"scope": "site-cache-only", "maxMatches": 100},
	}
}

func sanitizeItems(items []map[string]any, fields []string) ([]map[string]string, error) {
	out := make([]map[string]string, 0, len(items))
	for _, item := range items {
		for key, value := range item {
			if !safePublicField(key) {
				return nil, coded("SENSITIVE_RESPONSE_REFUSED", "browser response contained a forbidden field")
			}
			if text, ok := value.(string); ok {
				if _, err := sanitizeText(text); err != nil {
					return nil, err
				}
			}
		}
		projected := make(map[string]string, len(fields))
		for _, field := range fields {
			value, ok := item[field]
			if !ok {
				return nil, coded("TRANSPORT_RESPONSE_INVALID", "browser response omitted a projected field")
			}
			text, ok := value.(string)
			if !ok {
				return nil, coded("TRANSPORT_RESPONSE_INVALID", "browser response field was not text")
			}
			sanitized, err := sanitizeText(text)
			if err != nil {
				return nil, err
			}
			projected[field] = sanitized
		}
		out = append(out, projected)
	}
	return out, nil
}

func sanitizeText(value string) (string, error) {
	decision, err := EnforceOutbound(value)
	return decision.Value, err
}

func decodeSingleJSON(raw string, target any) error {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func decodeOutboundSingleJSON(raw string, target any) error {
	decision, err := EnforceOutbound(raw)
	if err != nil {
		return err
	}
	return decodeSingleJSON(decision.Value, target)
}

func digestItems(items []map[string]string) string {
	hash := sha256.New()
	for _, item := range items {
		hash.Write([]byte(digestItem(item)))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func digestItem(item map[string]string) string {
	data, _ := json.Marshal(item)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
