package chromectl

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/relux-works/mac-infra/internal/browsersession"
)

const (
	SlackOrigin            = "https://app.slack.com"
	SlackReadVersion       = 1
	MaxSlackRequestBytes   = 16 * 1024
	MaxSlackResponseBytes  = 256 * 1024
	maxSlackResponseDepth  = 32
	maxSlackResponseNodes  = 20_000
	maxSlackCursorBytes    = 512
	maxSlackSearchQuery    = 512
	maxSlackSearchPage     = 1_000
	slackReadGuardSentinel = "works.relux.mac-infra/slack-sealed-read/v1"
	slackReadPollInterval  = 100 * time.Millisecond
	slackBrowserDeadlineMS = 20_000
	slackRedactedMarker    = "[redacted]"
)

var (
	workspaceIDPattern     = regexp.MustCompile(`^T[A-Z0-9]{8,}$`)
	conversationIDPattern  = regexp.MustCompile(`^[CDG][A-Z0-9]{8,31}$`)
	slackTimestampPattern  = regexp.MustCompile(`^[0-9]{1,16}\.[0-9]{1,6}$`)
	slackTokenSpanPattern  = regexp.MustCompile(`(?i)(xox[a-z]-[a-z0-9-]{8,}|xapp-[a-z0-9-]{8,})`)
	bearerTokenSpanPattern = regexp.MustCompile(`(?i)(bearer[[:space:]]+[a-z0-9._~+/=-]{8,})`)
	jwtTokenSpanPattern    = regexp.MustCompile(`([A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}(?:\.[A-Za-z0-9_-]+)*)`)
)

type SlackReadRequest struct {
	Version int             `json:"version"`
	Method  string          `json:"method"`
	Args    json.RawMessage `json:"args"`
}

type SlackReadResult struct {
	Method string
	Data   any
}

type SlackReadError struct {
	Kind    string
	Message string
}

func (e *SlackReadError) Error() string {
	if e.Message == "" {
		return e.Kind
	}
	return e.Kind + ": " + e.Message
}

func DecodeSlackReadRequest(reader io.Reader) (SlackReadRequest, error) {
	limited := io.LimitReader(reader, MaxSlackRequestBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return SlackReadRequest{}, slackError("invalid-request", "read request body")
	}
	if len(data) > MaxSlackRequestBytes {
		return SlackReadRequest{}, slackError("request-too-large", "request exceeds 16 KiB")
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return SlackReadRequest{}, slackError("invalid-request", "request body is empty")
	}
	var request SlackReadRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return SlackReadRequest{}, slackError("invalid-request", "request must be one JSON envelope")
	}
	if err := requireJSONEOF(decoder); err != nil {
		return SlackReadRequest{}, slackError("invalid-request", "request must contain one JSON envelope")
	}
	if err := request.validate(""); err != nil {
		return SlackReadRequest{}, err
	}
	return request, nil
}

func (s Session) SlackRead(ctx context.Context, windowID, tabID, expectedOrigin, workspaceID string, request SlackReadRequest) (SlackReadResult, error) {
	windowID = strings.TrimSpace(windowID)
	tabID = strings.TrimSpace(tabID)
	expectedOrigin = strings.TrimSpace(expectedOrigin)
	workspaceID = strings.TrimSpace(workspaceID)
	if windowID == "" || tabID == "" {
		return SlackReadResult{}, slackError("invalid-target", "window id and tab id are required")
	}
	if expectedOrigin != SlackOrigin {
		return SlackReadResult{}, slackError("invalid-origin", "Slack sealed reads require https://app.slack.com")
	}
	if !workspaceIDPattern.MatchString(workspaceID) {
		return SlackReadResult{}, slackError("invalid-workspace", "workspace id must be a Slack T-prefixed id")
	}
	if err := request.validate(workspaceID); err != nil {
		return SlackReadResult{}, err
	}
	args, err := request.arguments(workspaceID)
	if err != nil {
		return SlackReadResult{}, err
	}
	jobID, err := newSlackJobID()
	if err != nil {
		return SlackReadResult{}, slackError("unavailable", "create bounded request identity")
	}
	startSource, err := slackStartJXA(windowID, tabID, expectedOrigin, workspaceID, jobID, request.Method, args)
	if err != nil {
		return SlackReadResult{}, err
	}
	raw, err := s.runJXAFromStdin(ctx, startSource, windowID+"/"+tabID)
	if err != nil {
		return SlackReadResult{}, err
	}
	start, err := parseSlackPageEnvelope(raw)
	if err != nil {
		return SlackReadResult{}, err
	}
	if start.Outcome != "started" {
		return SlackReadResult{}, slackPageOutcomeError(start.Outcome)
	}

	pollSource, err := slackPollJXA(windowID, tabID, expectedOrigin, workspaceID, jobID)
	if err != nil {
		return SlackReadResult{}, err
	}
	ticker := time.NewTicker(slackReadPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return SlackReadResult{}, slackError("timeout", "Slack read deadline expired")
		case <-ticker.C:
		}
		raw, err = s.runJXAFromStdin(ctx, pollSource, windowID+"/"+tabID)
		if err != nil {
			return SlackReadResult{}, err
		}
		poll, err := parseSlackPageEnvelope(raw)
		if err != nil {
			return SlackReadResult{}, err
		}
		switch poll.Outcome {
		case "pending":
			continue
		case "ok":
			if len(poll.Response) > MaxSlackResponseBytes {
				return SlackReadResult{}, slackError("response-too-large", "Slack response exceeded 256 KiB")
			}
			data, err := sanitizeSlackResponse([]byte(poll.Response))
			if err != nil {
				return SlackReadResult{}, err
			}
			return SlackReadResult{Method: request.Method, Data: data}, nil
		default:
			return SlackReadResult{}, slackPageOutcomeError(poll.Outcome)
		}
	}
}

func SlackReadErrorKind(err error) string {
	var slackErr *SlackReadError
	if errors.As(err, &slackErr) {
		return slackErr.Kind
	}
	switch {
	case errors.Is(err, browsersession.ErrOriginMismatch):
		return "origin-mismatch"
	case errors.Is(err, browsersession.ErrTargetMissing):
		return "target-missing"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "timeout"
	default:
		return "automation-unavailable"
	}
}

func SlackReadErrorMessage(kind string) string {
	switch kind {
	case "invalid-request", "request-too-large", "method-not-allowed", "invalid-arguments", "invalid-target", "invalid-origin", "invalid-workspace":
		return "request refused before browser execution"
	case "origin-mismatch":
		return "Slack tab origin changed; no request was started"
	case "workspace-mismatch":
		return "Slack tab workspace changed; no request was started"
	case "capability-unavailable":
		return "supported Slack browser authorization schema is unavailable"
	case "target-missing":
		return "exact Chrome target is no longer available"
	case "timeout":
		return "bounded Slack read timed out"
	case "response-too-large", "response-invalid", "response-too-deep", "response-too-complex", "response-key-collision":
		return "Slack response was refused by the bounded output policy"
	case "api-unavailable":
		return "Slack API request failed inside the authorized page"
	default:
		return "Slack sealed read is unavailable"
	}
}

func (r SlackReadRequest) validate(workspaceID string) error {
	if r.Version != SlackReadVersion {
		return slackError("invalid-request", "unsupported request version")
	}
	switch r.Method {
	case "auth.test", "conversations.list", "conversations.info", "conversations.history", "conversations.replies", "users.list", "search.messages":
	default:
		return slackError("method-not-allowed", "method is not in the compiled read allowlist")
	}
	_, err := r.arguments(workspaceID)
	return err
}

func (r SlackReadRequest) arguments(workspaceID string) (map[string]any, error) {
	raw := bytes.TrimSpace(r.Args)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		raw = []byte("{}")
	}
	switch r.Method {
	case "auth.test":
		var args struct{}
		if err := decodeSlackArguments(raw, &args); err != nil {
			return nil, slackError("invalid-arguments", "auth.test accepts no arguments")
		}
		return map[string]any{}, nil
	case "conversations.list":
		var args struct {
			Cursor          string `json:"cursor,omitempty"`
			ExcludeArchived *bool  `json:"exclude_archived,omitempty"`
			Limit           *int   `json:"limit,omitempty"`
			Types           string `json:"types,omitempty"`
		}
		if err := decodeSlackArguments(raw, &args); err != nil {
			return nil, slackError("invalid-arguments", "conversations.list arguments are malformed or unknown")
		}
		out := map[string]any{}
		if err := addSlackCursor(out, args.Cursor); err != nil {
			return nil, err
		}
		if args.ExcludeArchived != nil {
			out["exclude_archived"] = *args.ExcludeArchived
		}
		if args.Limit != nil {
			if *args.Limit < 1 || *args.Limit > 100 {
				return nil, slackError("invalid-arguments", "limit must be between 1 and 100")
			}
			out["limit"] = *args.Limit
		}
		if args.Types != "" {
			allowed := map[string]bool{"public_channel": true, "private_channel": true, "mpim": true, "im": true}
			for _, item := range strings.Split(args.Types, ",") {
				if !allowed[strings.TrimSpace(item)] {
					return nil, slackError("invalid-arguments", "types contains an unsupported conversation type")
				}
			}
			out["types"] = args.Types
		}
		return out, nil
	case "conversations.info":
		var args struct {
			Channel           string `json:"channel"`
			IncludeLocale     *bool  `json:"include_locale,omitempty"`
			IncludeNumMembers *bool  `json:"include_num_members,omitempty"`
		}
		if err := decodeSlackArguments(raw, &args); err != nil {
			return nil, slackError("invalid-arguments", "conversations.info arguments are malformed or unknown")
		}
		out := map[string]any{}
		if err := addSlackConversationID(out, "channel", args.Channel); err != nil {
			return nil, err
		}
		addSlackBool(out, "include_locale", args.IncludeLocale)
		addSlackBool(out, "include_num_members", args.IncludeNumMembers)
		return out, nil
	case "conversations.history":
		var args struct {
			Channel            string `json:"channel"`
			Cursor             string `json:"cursor,omitempty"`
			Limit              *int   `json:"limit,omitempty"`
			Oldest             string `json:"oldest,omitempty"`
			Latest             string `json:"latest,omitempty"`
			Inclusive          *bool  `json:"inclusive,omitempty"`
			IncludeAllMetadata *bool  `json:"include_all_metadata,omitempty"`
		}
		if err := decodeSlackArguments(raw, &args); err != nil {
			return nil, slackError("invalid-arguments", "conversations.history arguments are malformed or unknown")
		}
		out := map[string]any{}
		if err := addSlackConversationID(out, "channel", args.Channel); err != nil {
			return nil, err
		}
		if err := addSlackPagination(out, args.Cursor, args.Limit); err != nil {
			return nil, err
		}
		if err := addSlackTimestamp(out, "oldest", args.Oldest, false); err != nil {
			return nil, err
		}
		if err := addSlackTimestamp(out, "latest", args.Latest, false); err != nil {
			return nil, err
		}
		addSlackBool(out, "inclusive", args.Inclusive)
		addSlackBool(out, "include_all_metadata", args.IncludeAllMetadata)
		return out, nil
	case "conversations.replies":
		var args struct {
			Channel            string `json:"channel"`
			TS                 string `json:"ts"`
			Cursor             string `json:"cursor,omitempty"`
			Limit              *int   `json:"limit,omitempty"`
			Oldest             string `json:"oldest,omitempty"`
			Latest             string `json:"latest,omitempty"`
			Inclusive          *bool  `json:"inclusive,omitempty"`
			IncludeAllMetadata *bool  `json:"include_all_metadata,omitempty"`
		}
		if err := decodeSlackArguments(raw, &args); err != nil {
			return nil, slackError("invalid-arguments", "conversations.replies arguments are malformed or unknown")
		}
		out := map[string]any{}
		if err := addSlackConversationID(out, "channel", args.Channel); err != nil {
			return nil, err
		}
		if err := addSlackTimestamp(out, "ts", args.TS, true); err != nil {
			return nil, err
		}
		if err := addSlackPagination(out, args.Cursor, args.Limit); err != nil {
			return nil, err
		}
		if err := addSlackTimestamp(out, "oldest", args.Oldest, false); err != nil {
			return nil, err
		}
		if err := addSlackTimestamp(out, "latest", args.Latest, false); err != nil {
			return nil, err
		}
		addSlackBool(out, "inclusive", args.Inclusive)
		addSlackBool(out, "include_all_metadata", args.IncludeAllMetadata)
		return out, nil
	case "users.list":
		var args struct {
			Cursor        string  `json:"cursor,omitempty"`
			Limit         *int    `json:"limit,omitempty"`
			IncludeLocale *bool   `json:"include_locale,omitempty"`
			TeamID        *string `json:"team_id,omitempty"`
		}
		if err := decodeSlackArguments(raw, &args); err != nil {
			return nil, slackError("invalid-arguments", "users.list arguments are malformed or unknown")
		}
		out := map[string]any{}
		if err := addSlackPagination(out, args.Cursor, args.Limit); err != nil {
			return nil, err
		}
		addSlackBool(out, "include_locale", args.IncludeLocale)
		if err := addSlackTeamID(out, args.TeamID, workspaceID); err != nil {
			return nil, err
		}
		return out, nil
	case "search.messages":
		var args struct {
			Query     string  `json:"query"`
			Count     *int    `json:"count,omitempty"`
			Page      *int    `json:"page,omitempty"`
			Cursor    string  `json:"cursor,omitempty"`
			Sort      *string `json:"sort,omitempty"`
			SortDir   *string `json:"sort_dir,omitempty"`
			Highlight *bool   `json:"highlight,omitempty"`
			TeamID    *string `json:"team_id,omitempty"`
		}
		if err := decodeSlackArguments(raw, &args); err != nil {
			return nil, slackError("invalid-arguments", "search.messages arguments are malformed or unknown")
		}
		out := map[string]any{}
		if strings.TrimSpace(args.Query) == "" || len(args.Query) > maxSlackSearchQuery || containsTokenShape(args.Query) {
			return nil, slackError("invalid-arguments", "query is required, bounded to 512 bytes, and must not be secret-shaped")
		}
		out["query"] = args.Query
		if args.Count != nil {
			if *args.Count < 1 || *args.Count > 100 {
				return nil, slackError("invalid-arguments", "count must be between 1 and 100")
			}
			out["count"] = *args.Count
		}
		if args.Page != nil {
			if *args.Page < 1 || *args.Page > maxSlackSearchPage {
				return nil, slackError("invalid-arguments", "page must be between 1 and 1000")
			}
			out["page"] = *args.Page
		}
		if err := addSlackCursor(out, args.Cursor); err != nil {
			return nil, err
		}
		if err := addSlackEnum(out, "sort", args.Sort, "score", "timestamp"); err != nil {
			return nil, err
		}
		if err := addSlackEnum(out, "sort_dir", args.SortDir, "asc", "desc"); err != nil {
			return nil, err
		}
		addSlackBool(out, "highlight", args.Highlight)
		if err := addSlackTeamID(out, args.TeamID, workspaceID); err != nil {
			return nil, err
		}
		return out, nil
	default:
		return nil, slackError("method-not-allowed", "method is not in the compiled read allowlist")
	}
}

func decodeSlackArguments(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func addSlackConversationID(out map[string]any, key, value string) error {
	if !conversationIDPattern.MatchString(value) {
		return slackError("invalid-arguments", key+" must be a Slack conversation id")
	}
	out[key] = value
	return nil
}

func addSlackCursor(out map[string]any, cursor string) error {
	if cursor == "" {
		return nil
	}
	if len(cursor) > maxSlackCursorBytes || containsTokenShape(cursor) {
		return slackError("invalid-arguments", "cursor is oversized or secret-shaped")
	}
	out["cursor"] = cursor
	return nil
}

func addSlackPagination(out map[string]any, cursor string, limit *int) error {
	if err := addSlackCursor(out, cursor); err != nil {
		return err
	}
	if limit != nil {
		if *limit < 1 || *limit > 100 {
			return slackError("invalid-arguments", "limit must be between 1 and 100")
		}
		out["limit"] = *limit
	}
	return nil
}

func addSlackTimestamp(out map[string]any, key, value string, required bool) error {
	if value == "" && !required {
		return nil
	}
	if !slackTimestampPattern.MatchString(value) || containsTokenShape(value) {
		return slackError("invalid-arguments", key+" must be a Slack timestamp")
	}
	out[key] = value
	return nil
}

func addSlackBool(out map[string]any, key string, value *bool) {
	if value != nil {
		out[key] = *value
	}
}

func addSlackTeamID(out map[string]any, teamID *string, workspaceID string) error {
	if teamID == nil {
		return nil
	}
	if !workspaceIDPattern.MatchString(*teamID) || len(*teamID) > 32 || containsTokenShape(*teamID) {
		return slackError("invalid-arguments", "team_id must be a Slack workspace id")
	}
	if workspaceID != "" && *teamID != workspaceID {
		return slackError("invalid-arguments", "team_id must match the configured workspace")
	}
	out["team_id"] = *teamID
	return nil
}

func addSlackEnum(out map[string]any, key string, value *string, allowed ...string) error {
	if value == nil {
		return nil
	}
	for _, candidate := range allowed {
		if *value == candidate {
			out[key] = *value
			return nil
		}
	}
	return slackError("invalid-arguments", key+" contains an unsupported value")
}

type slackPageEnvelope struct {
	Sentinel string `json:"__macSlackSealedRead"`
	Outcome  string `json:"outcome"`
	Response string `json:"response,omitempty"`
}

func parseSlackPageEnvelope(raw string) (slackPageEnvelope, error) {
	if strings.TrimSpace(raw) == "" {
		return slackPageEnvelope{}, slackError("response-invalid", "empty page response")
	}
	var envelope slackPageEnvelope
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil || envelope.Sentinel != slackReadGuardSentinel || envelope.Outcome == "" {
		return slackPageEnvelope{}, slackError("response-invalid", "malformed page response")
	}
	return envelope, nil
}

func slackPageOutcomeError(outcome string) error {
	switch outcome {
	case "origin-mismatch":
		return slackError("origin-mismatch", "origin guard refused")
	case "workspace-mismatch":
		return slackError("workspace-mismatch", "workspace guard refused")
	case "capability-unavailable":
		return slackError("capability-unavailable", "supported authorization schema missing")
	case "response-too-large":
		return slackError("response-too-large", "page response exceeded bound")
	case "timeout":
		return slackError("timeout", "page request deadline expired")
	case "api-unavailable":
		return slackError("api-unavailable", "page request failed")
	default:
		return slackError("response-invalid", "unknown page outcome")
	}
}

func slackStartJXA(windowID, tabID, origin, workspaceID, jobID, method string, args map[string]any) (string, error) {
	pageSource, err := slackStartPageJavaScript(origin, workspaceID, jobID, method, args)
	if err != nil {
		return "", err
	}
	return exactChromeJXA(windowID, tabID, pageSource), nil
}

func slackPollJXA(windowID, tabID, origin, workspaceID, jobID string) (string, error) {
	pageSource, err := slackPollPageJavaScript(origin, workspaceID, jobID)
	if err != nil {
		return "", err
	}
	return exactChromeJXA(windowID, tabID, pageSource), nil
}

func exactChromeJXA(windowID, tabID, pageSource string) string {
	windowJSON, _ := json.Marshal(windowID)
	tabJSON, _ := json.Marshal(tabID)
	pageJSON, _ := json.Marshal(pageSource)
	return fmt.Sprintf(`function run(){const c=Application("Google Chrome");const ws=c.windows.whose({id:Number(%s)})();if(!ws.length)throw new Error("Chrome target window is no longer open");const ts=ws[0].tabs.whose({id:Number(%s)})();if(!ts.length)throw new Error("Chrome target tab is no longer open");return c.execute(ts[0],{javascript:%s});}`, windowJSON, tabJSON, pageJSON)
}

func slackStartPageJavaScript(origin, workspaceID, jobID, method string, args map[string]any) (string, error) {
	originJSON, _ := json.Marshal(origin)
	workspaceJSON, _ := json.Marshal(workspaceID)
	jobJSON, _ := json.Marshal(jobID)
	methodJSON, _ := json.Marshal(method)
	argsJSON, err := json.Marshal(args)
	if err != nil {
		return "", slackError("invalid-arguments", "encode allowlisted arguments")
	}
	sentinelJSON, _ := json.Marshal(slackReadGuardSentinel)
	return fmt.Sprintf(`(() => {
  const __guard = %s, __origin = %s, __workspace = %s, __jobKey = %s;
  const __reply = outcome => JSON.stringify({__macSlackSealedRead:__guard,outcome});
  if (location.origin !== __origin) return __reply("origin-mismatch");
  const __prefix = "/client/" + __workspace;
  if (!(location.pathname === __prefix || location.pathname.startsWith(__prefix + "/"))) return __reply("workspace-mismatch");
  let __config;
  try {
    const __raw = localStorage.getItem("localConfig_v2");
    if (!__raw) return __reply("capability-unavailable");
    __config = JSON.parse(__raw);
  } catch (_) { return __reply("capability-unavailable"); }
  const __teams = __config && __config.teams;
  let __team = __teams && !Array.isArray(__teams) ? __teams[__workspace] : null;
  if (!__team && Array.isArray(__teams)) __team = __teams.find(t => t && (t.id === __workspace || t.team_id === __workspace));
  const __token = __team && __team.token;
  if (typeof __token !== "string" || !/^xoxc-[A-Za-z0-9-]{8,}$/.test(__token)) return __reply("capability-unavailable");
  if (Object.prototype.hasOwnProperty.call(window, __jobKey)) return __reply("capability-unavailable");
  const __job = {state:"pending"};
  Object.defineProperty(window, __jobKey, {value:__job,writable:false,configurable:true,enumerable:false});
  const __controller = new AbortController();
  const __timer = setTimeout(() => __controller.abort(), %d);
  const __body = new URLSearchParams();
  __body.set("token", __token);
  for (const [k,v] of Object.entries(%s)) __body.set(k, String(v));
  fetch("/api/" + %s, {method:"POST",credentials:"include",headers:{"Content-Type":"application/x-www-form-urlencoded;charset=UTF-8"},body:__body.toString(),signal:__controller.signal})
    .then(async response => {
      if (!response.ok || !response.body) { __job.state="api-unavailable"; return; }
      const reader = response.body.getReader();
      const chunks = []; let size = 0;
      while (true) {
        const part = await reader.read();
        if (part.done) break;
        size += part.value.byteLength;
        if (size > %d) { try { await reader.cancel(); } catch (_) {} __job.state="response-too-large"; return; }
        chunks.push(part.value);
      }
      const merged = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { merged.set(chunk, offset); offset += chunk.byteLength; }
      __job.response = new TextDecoder().decode(merged);
      __job.state = "ok";
    })
    .catch(error => { __job.state = error && error.name === "AbortError" ? "timeout" : "api-unavailable"; })
    .finally(() => clearTimeout(__timer));
  return __reply("started");
})()`, sentinelJSON, originJSON, workspaceJSON, jobJSON, slackBrowserDeadlineMS, string(argsJSON), methodJSON, MaxSlackResponseBytes), nil
}

func slackPollPageJavaScript(origin, workspaceID, jobID string) (string, error) {
	originJSON, _ := json.Marshal(origin)
	workspaceJSON, _ := json.Marshal(workspaceID)
	jobJSON, _ := json.Marshal(jobID)
	sentinelJSON, _ := json.Marshal(slackReadGuardSentinel)
	return fmt.Sprintf(`(() => {
  const __guard = %s, __origin = %s, __workspace = %s, __jobKey = %s;
  const __reply = (outcome,response) => JSON.stringify({__macSlackSealedRead:__guard,outcome,response});
  if (location.origin !== __origin) return __reply("origin-mismatch");
  const __prefix = "/client/" + __workspace;
  if (!(location.pathname === __prefix || location.pathname.startsWith(__prefix + "/"))) return __reply("workspace-mismatch");
  const __job = window[__jobKey];
  if (!__job || typeof __job.state !== "string") return __reply("capability-unavailable");
  if (__job.state === "pending") return __reply("pending");
  const __state = __job.state, __response = typeof __job.response === "string" ? __job.response : "";
  try { delete window[__jobKey]; } catch (_) {}
  return __reply(__state, __response);
})()`, sentinelJSON, originJSON, workspaceJSON, jobJSON), nil
}

func sanitizeSlackResponse(raw []byte) (any, error) {
	if len(raw) == 0 || len(raw) > MaxSlackResponseBytes {
		return nil, slackError("response-too-large", "Slack response is empty or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	nodes := 0
	sanitized, err := decodeSanitizedSlackValue(decoder, 0, &nodes)
	if err != nil {
		return nil, err
	}
	if requireJSONEOF(decoder) != nil {
		return nil, slackError("response-invalid", "Slack response is not one JSON value")
	}
	return sanitized, nil
}

// decodeSanitizedSlackValue consumes object members in source order so duplicate
// decoded names cannot be collapsed before collision and raw-node checks run.
func decodeSanitizedSlackValue(decoder *json.Decoder, depth int, nodes *int) (any, error) {
	*nodes = *nodes + 1
	if *nodes > maxSlackResponseNodes {
		return nil, slackError("response-too-complex", "Slack response node count exceeds bound")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, slackError("response-invalid", "Slack response JSON is malformed")
	}

	if delim, ok := token.(json.Delim); ok {
		if depth+1 > maxSlackResponseDepth {
			return nil, slackError("response-too-deep", "Slack response nesting exceeds bound")
		}
		switch delim {
		case '{':
			out := make(map[string]any)
			collision := false
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, slackError("response-invalid", "Slack response JSON is malformed")
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, slackError("response-invalid", "Slack response object key is malformed")
				}
				sanitizedKey := sanitizeSlackString(key)
				_, exists := out[sanitizedKey]
				sanitized, err := decodeSanitizedSlackValue(decoder, depth+1, nodes)
				if err != nil {
					return nil, err
				}
				if exists {
					collision = true
					continue
				}
				if isSlackSecretKey(key) {
					out[sanitizedKey] = slackRedactedMarker
				} else {
					out[sanitizedKey] = sanitized
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return nil, slackError("response-invalid", "Slack response JSON is malformed")
			}
			if collision {
				return nil, slackError("response-key-collision", "Slack response keys collide after redaction")
			}
			return out, nil
		case '[':
			out := make([]any, 0)
			for decoder.More() {
				sanitized, err := decodeSanitizedSlackValue(decoder, depth+1, nodes)
				if err != nil {
					return nil, err
				}
				out = append(out, sanitized)
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return nil, slackError("response-invalid", "Slack response JSON is malformed")
			}
			return out, nil
		default:
			return nil, slackError("response-invalid", "Slack response JSON is malformed")
		}
	}

	switch typed := token.(type) {
	case string:
		return sanitizeSlackString(typed), nil
	case json.Number, bool, nil:
		return typed, nil
	default:
		return nil, slackError("response-invalid", "Slack response JSON contains an unsupported value")
	}
}

func sanitizeSlackString(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToLower(trimmed), "https://") || strings.HasPrefix(strings.ToLower(trimmed), "http://") {
		start := strings.Index(value, trimmed)
		value = value[:start] + browsersession.RedactSensitiveURL(trimmed) + value[start+len(trimmed):]
	}
	return redactSlackTokenSpans(value)
}

func isSlackSecretKey(key string) bool {
	compact := strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(strings.ToLower(strings.TrimSpace(key)))
	switch compact {
	case "apikey", "authorization", "clientsecret", "cookie", "cookies", "credential", "credentials", "password", "passwd", "privatekey", "session", "sessionid":
		return true
	default:
		return strings.HasSuffix(compact, "token") || strings.HasSuffix(compact, "secret") || strings.Contains(compact, "cookie")
	}
}

func containsTokenShape(value string) bool {
	return len(findSlackTokenSpans(value)) != 0
}

type slackTokenSpan struct {
	start int
	end   int
}

func redactSlackTokenSpans(value string) string {
	spans := findSlackTokenSpans(value)
	if len(spans) == 0 {
		return value
	}
	var sanitized strings.Builder
	sanitized.Grow(len(value))
	cursor := 0
	for _, span := range spans {
		sanitized.WriteString(value[cursor:span.start])
		sanitized.WriteString(slackRedactedMarker)
		cursor = span.end
	}
	sanitized.WriteString(value[cursor:])
	return sanitized.String()
}

func findSlackTokenSpans(value string) []slackTokenSpan {
	var spans []slackTokenSpan
	spans = appendSlackTokenSpans(spans, value, slackTokenSpanPattern)
	spans = appendSlackTokenSpans(spans, value, bearerTokenSpanPattern)
	spans = appendSlackTokenSpans(spans, value, jwtTokenSpanPattern)
	if len(spans) < 2 {
		return spans
	}
	sort.Slice(spans, func(left, right int) bool {
		if spans[left].start == spans[right].start {
			return spans[left].end > spans[right].end
		}
		return spans[left].start < spans[right].start
	})
	// Reuse the collection buffer while replacing it with ordered, disjoint spans.
	merged := spans[:0]
	for _, span := range spans {
		if len(merged) == 0 || span.start >= merged[len(merged)-1].end {
			merged = append(merged, span)
			continue
		}
		if span.end > merged[len(merged)-1].end {
			merged[len(merged)-1].end = span.end
		}
	}
	return merged
}

func appendSlackTokenSpans(spans []slackTokenSpan, value string, pattern *regexp.Regexp) []slackTokenSpan {
	for _, match := range pattern.FindAllStringSubmatchIndex(value, -1) {
		spans = append(spans, slackTokenSpan{start: match[2], end: match[3]})
	}
	return spans
}

func (s Session) runJXAFromStdin(ctx context.Context, source, target string) (string, error) {
	path := strings.TrimSpace(s.OsaScriptPath)
	if path == "" {
		path = "/usr/bin/osascript"
	}
	cmd := exec.CommandContext(ctx, path, "-l", "JavaScript")
	cmd.Stdin = strings.NewReader(source)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		if detail == "" {
			detail = err.Error()
		}
		lower := strings.ToLower(detail)
		if strings.Contains(lower, "target window is no longer open") || strings.Contains(lower, "target tab is no longer open") {
			return "", &browsersession.TargetMissingError{Browser: browsersession.BrowserChrome, Target: target, Detail: "exact Chrome target is no longer available"}
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) {
			return "", slackError("timeout", "Apple Events call exceeded deadline")
		}
		return "", slackError("automation-unavailable", "Chrome Apple Events failed")
	}
	return strings.TrimRight(stdout.String(), "\n"), nil
}

func newSlackJobID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "__macInfraSlackRead_" + hex.EncodeToString(random[:]), nil
}

func slackError(kind, message string) error {
	return &SlackReadError{Kind: kind, Message: message}
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err == nil {
		return errors.New("trailing JSON value")
	} else {
		return err
	}
}
