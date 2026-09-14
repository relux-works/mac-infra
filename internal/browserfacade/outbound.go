package browserfacade

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/relux-works/mac-infra/internal/docsanitize"
)

// OutboundState is the single normalized decision vocabulary for anything
// that can leave the browser-site facade or enter its searchable cache.
type OutboundState string

const (
	OutboundClean    OutboundState = "clean"
	OutboundRedacted OutboundState = "redacted"
	OutboundRefused  OutboundState = "refused"
	OutboundUnknown  OutboundState = "unknown"
)

// OutboundDecision carries the safe replacement only for clean or redacted
// input. Refused and unknown decisions never retain the inspected input.
type OutboundDecision struct {
	State OutboundState
	Value string
}

var (
	outboundURLPattern        = regexp.MustCompile(`(?i)\bhttps?://[^\\\s"'<>]+`)
	outboundSecretPattern     = regexp.MustCompile(`(?i)(?:authorization\s*:|proxy-authorization\s*:|set-cookie\s*:|cookie\s*:|bearer\s+[a-z0-9._~+/=-]{8,}|x-api-key\s*:|x-auth-token\s*:|(?:client[_-]?secret|refresh[_-]?token|access[_-]?token|api[_-]?key|signature)\s*[=:]\s*[^\s,;]{4,}|gh[pousr]_[a-z0-9]{16,}|github_pat_[a-z0-9_]{20,}|gl(?:pat|ptt|ft|rt|cbt|imt|soat|oas|ffct|agent|dt)-[a-z0-9_-]{10,}|(?:akia|asia)[a-z0-9]{16}|sk-(?:proj-)?[a-z0-9_-]{16,}|sk_(?:live|test)_[a-z0-9]{16,}|xox[baprs]-[a-z0-9-]{10,}|npm_[a-z0-9]{16,}|[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\.[a-z0-9_-]{8,})`)
	encodedSecretHintPattern  = regexp.MustCompile(`(?i)(?:https?|bearer|authorization|token|secret|api[_-]?key|signature)(?:%[0-9a-f]{2})`)
	outboundAssignmentPattern = regexp.MustCompile(`(?i)\b([a-z][a-z0-9_. -]{0,63})\s*[=:]\s*[^\s,;]{1,}`)
	opaqueCredentialPattern   = regexp.MustCompile(`\b[A-Za-z0-9_-]{32,256}\b`)
)

const (
	maximumOutboundBytes      = 4 * 1024 * 1024
	maximumNormalizationDepth = 4
	maximumDerivedVariants    = 16
)

// EnforceOutbound is the sole secret-scanning decision point for facade
// outputs, cache bytes, adapter metadata, and transport error details.
func EnforceOutbound(raw string) (OutboundDecision, error) {
	decision := scanOutbound(raw, 0)
	switch decision.State {
	case OutboundClean, OutboundRedacted:
		return decision, nil
	case OutboundRefused:
		return OutboundDecision{State: OutboundRefused}, coded("SENSITIVE_RESPONSE_REFUSED", "outbound secret boundary refused sensitive material")
	default:
		return OutboundDecision{State: OutboundUnknown}, coded("SENSITIVE_RESPONSE_UNKNOWN", "outbound secret boundary could not safely classify material")
	}
}

// WriteOutbound buffers must already be complete. It guarantees that a
// renderer cannot partially write before the central boundary has decided.
func WriteOutbound(writer io.Writer, raw string) error {
	decision, err := EnforceOutbound(raw)
	if err != nil {
		return err
	}
	_, err = io.WriteString(writer, decision.Value)
	return err
}

func enforceOutboundValue(value any) error {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return coded("INTERNAL_ERROR", "encode outbound value")
	}
	_, err := EnforceOutbound(buffer.String())
	return err
}

func scanOutbound(raw string, depth int) OutboundDecision {
	if depth > maximumNormalizationDepth || len(raw) > maximumOutboundBytes || !utf8.ValidString(raw) || hasAmbiguousControl(raw) {
		return OutboundDecision{State: OutboundUnknown}
	}
	if docsanitize.IsPlaceholder(raw) {
		return OutboundDecision{State: OutboundClean, Value: raw}
	}
	redacted, remainder, urlState := sanitizeOutboundURLs(raw, depth)
	if urlState == OutboundRefused || urlState == OutboundUnknown {
		return OutboundDecision{State: urlState}
	}
	jsonShaped := isJSONObjectOrArray(redacted)
	if jsonShaped {
		if state := inspectJSONShape(redacted, depth); state == OutboundRefused || state == OutboundUnknown {
			return OutboundDecision{State: state}
		}
		if urlState == OutboundRedacted {
			rescanned := scanOutbound(redacted, depth+1)
			if rescanned.State != OutboundClean {
				return OutboundDecision{State: OutboundUnknown}
			}
			return OutboundDecision{State: OutboundRedacted, Value: rescanned.Value}
		}
		return OutboundDecision{State: OutboundClean, Value: raw}
	}
	if outboundSecretPattern.MatchString(remainder) {
		return OutboundDecision{State: OutboundRefused}
	}
	if state := inspectSensitiveAssignments(remainder); state == OutboundRefused || state == OutboundUnknown {
		return OutboundDecision{State: state}
	}
	if looksLikeOpaqueCredential(remainder) {
		return OutboundDecision{State: OutboundUnknown}
	}
	if state := inspectNormalizedVariants(remainder, depth); state == OutboundRefused || state == OutboundUnknown {
		return OutboundDecision{State: state}
	}
	if urlState == OutboundRedacted {
		rescanned := scanOutbound(redacted, depth+1)
		if rescanned.State == OutboundRefused || rescanned.State == OutboundUnknown {
			return OutboundDecision{State: rescanned.State}
		}
		if rescanned.State == OutboundRedacted {
			return OutboundDecision{State: OutboundUnknown}
		}
		return OutboundDecision{State: OutboundRedacted, Value: rescanned.Value}
	}
	return OutboundDecision{State: OutboundClean, Value: raw}
}

func hasAmbiguousControl(raw string) bool {
	for _, char := range raw {
		if char < 0x20 && char != '\n' && char != '\r' && char != '\t' {
			return true
		}
	}
	return false
}

func sanitizeOutboundURLs(raw string, depth int) (string, string, OutboundState) {
	indices := outboundURLPattern.FindAllStringIndex(raw, -1)
	if len(indices) == 0 {
		return raw, raw, OutboundClean
	}
	var safe, remainder strings.Builder
	state := OutboundClean
	last := 0
	for _, bounds := range indices {
		safe.WriteString(raw[last:bounds[0]])
		remainder.WriteString(raw[last:bounds[0]])
		candidate := raw[bounds[0]:bounds[1]]
		replacement, candidateState := sanitizeOutboundURL(candidate, depth)
		if candidateState == OutboundRefused || candidateState == OutboundUnknown {
			return "", "", candidateState
		}
		if candidateState == OutboundRedacted {
			state = OutboundRedacted
		}
		safe.WriteString(replacement)
		remainder.WriteByte(' ')
		last = bounds[1]
	}
	safe.WriteString(raw[last:])
	remainder.WriteString(raw[last:])
	return safe.String(), remainder.String(), state
}

func sanitizeOutboundURL(raw string, depth int) (string, OutboundState) {
	parsed, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" {
		return "", OutboundUnknown
	}
	state := OutboundClean
	if parsed.User != nil {
		parsed.User = nil
		state = OutboundRedacted
	}
	if componentState := inspectOutboundURLHostAndPath(parsed, depth); componentState != OutboundClean {
		return "", componentState
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return "", OutboundUnknown
	}
	queryChanged := false
	for key, values := range query {
		keyDecision := scanNestedValue(key, depth+1)
		if keyDecision == OutboundUnknown {
			return "", OutboundUnknown
		}
		if keyDecision == OutboundRefused || keyDecision == OutboundRedacted {
			return "", OutboundRefused
		}
		if outboundNameState(key) != OutboundClean {
			for index, value := range values {
				if value != "[redacted]" {
					values[index] = "[redacted]"
					queryChanged = true
					state = OutboundRedacted
				}
			}
			query[key] = values
			continue
		}
		for _, value := range values {
			decision := scanNestedValue(value, depth+1)
			if decision == OutboundUnknown {
				return "", OutboundUnknown
			}
			if decision == OutboundRefused || decision == OutboundRedacted {
				return "", OutboundRefused
			}
		}
	}
	if queryChanged {
		parsed.RawQuery = query.Encode()
	}
	if parsed.Fragment != "" && parsed.Fragment != "[redacted]" {
		parsed.Fragment = "[redacted]"
		state = OutboundRedacted
	}
	return parsed.String(), state
}

func inspectOutboundURLHostAndPath(parsed *url.URL, depth int) OutboundState {
	hostname := parsed.Hostname()
	if hostname == "" {
		return OutboundUnknown
	}
	if state := inspectOutboundURLComponent(hostname, depth+1); state != OutboundClean {
		return state
	}
	for _, encoded := range strings.Split(parsed.EscapedPath(), "/") {
		if encoded == "" {
			continue
		}
		component, state := decodeOutboundURLComponent(encoded)
		if state != OutboundClean {
			return state
		}
		if state := inspectOutboundURLComponent(component, depth+1); state != OutboundClean {
			return state
		}
	}
	return OutboundClean
}

func inspectOutboundURLComponent(component string, depth int) OutboundState {
	decision := scanNestedValue(component, depth)
	if decision == OutboundUnknown {
		return OutboundUnknown
	}
	if decision == OutboundRefused || decision == OutboundRedacted {
		return OutboundRefused
	}
	return outboundNameState(component)
}

func decodeOutboundURLComponent(raw string) (string, OutboundState) {
	current := raw
	for round := 0; round < maximumNormalizationDepth && hasPercentEscape(current); round++ {
		decoded, err := url.PathUnescape(current)
		if err != nil {
			return "", OutboundUnknown
		}
		if decoded == current {
			break
		}
		current = decoded
	}
	if strings.Contains(current, "%") {
		return "", OutboundUnknown
	}
	return current, OutboundClean
}

func hasPercentEscape(raw string) bool {
	for index := 0; index+2 < len(raw); index++ {
		if raw[index] == '%' && isHexByte(raw[index+1]) && isHexByte(raw[index+2]) {
			return true
		}
	}
	return false
}

func isHexByte(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func scanNestedValue(value string, depth int) OutboundState {
	decision := scanOutbound(value, depth)
	return decision.State
}

type normalizationVariant struct {
	value string
	depth int
}

func inspectNormalizedVariants(raw string, depth int) OutboundState {
	queue := []normalizationVariant{{value: raw, depth: depth}}
	seen := map[string]struct{}{raw: {}}
	derivedCount, derivedBytes := 0, 0
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current.depth >= maximumNormalizationDepth {
			if hasTransformHint(current.value) {
				return OutboundUnknown
			}
			continue
		}
		variants, state := deriveNormalizedVariants(current.value)
		if state != OutboundClean {
			return state
		}
		for _, variant := range variants {
			if _, duplicate := seen[variant]; duplicate {
				continue
			}
			seen[variant] = struct{}{}
			derivedCount++
			derivedBytes += len(variant)
			if derivedCount > maximumDerivedVariants || derivedBytes > maximumOutboundBytes*4 {
				return OutboundUnknown
			}
			safe, remainder, urlState := sanitizeOutboundURLs(variant, current.depth+1)
			if urlState == OutboundRefused || urlState == OutboundUnknown {
				return urlState
			}
			if urlState == OutboundRedacted || outboundSecretPattern.MatchString(remainder) {
				return OutboundRefused
			}
			if state := inspectSensitiveAssignments(remainder); state != OutboundClean {
				return state
			}
			if looksLikeOpaqueCredential(remainder) {
				return OutboundUnknown
			}
			if state := inspectJSONShape(safe, current.depth+1); state == OutboundRefused || state == OutboundUnknown {
				return state
			}
			queue = append(queue, normalizationVariant{value: variant, depth: current.depth + 1})
		}
	}
	return OutboundClean
}

func deriveNormalizedVariants(raw string) ([]string, OutboundState) {
	variants := make([]string, 0, 2)
	if strings.Contains(raw, "%") {
		decoded, err := url.QueryUnescape(raw)
		if err != nil {
			if encodedSecretHintPattern.MatchString(raw) {
				return nil, OutboundUnknown
			}
		} else if decoded != raw {
			variants = append(variants, decoded)
		}
	}
	if strings.Contains(raw, `\`) {
		decoded, changed, ambiguous := decodeBackslashVariant(raw)
		if ambiguous && hasSecretHint(raw) {
			return nil, OutboundUnknown
		}
		if changed {
			variants = append(variants, decoded)
		}
	}
	return variants, OutboundClean
}

func decodeBackslashVariant(raw string) (string, bool, bool) {
	var builder strings.Builder
	changed, ambiguous := false, false
	for index := 0; index < len(raw); index++ {
		if raw[index] != '\\' {
			builder.WriteByte(raw[index])
			continue
		}
		if index+1 >= len(raw) {
			builder.WriteByte(raw[index])
			ambiguous = true
			continue
		}
		next := raw[index+1]
		switch next {
		case '\\', '/', '"':
			builder.WriteByte(next)
			index++
			changed = true
		case 'b', 'f', 'n', 'r', 't':
			decoded := map[byte]byte{'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t'}[next]
			builder.WriteByte(decoded)
			index++
			changed = true
		case 'u':
			if index+5 >= len(raw) {
				builder.WriteByte('\\')
				ambiguous = true
				continue
			}
			value, err := strconv.ParseUint(raw[index+2:index+6], 16, 16)
			if err != nil || value >= 0xD800 && value <= 0xDFFF {
				builder.WriteByte('\\')
				ambiguous = true
				continue
			}
			builder.WriteRune(rune(value))
			index += 5
			changed = true
		default:
			builder.WriteByte('\\')
			ambiguous = true
		}
	}
	return builder.String(), changed, ambiguous
}

func hasTransformHint(raw string) bool {
	return strings.Contains(raw, `\`) && hasSecretHint(raw) || strings.Contains(raw, "%") && encodedSecretHintPattern.MatchString(raw)
}

func hasSecretHint(raw string) bool {
	lower := strings.ToLower(raw)
	for _, hint := range []string{"http", "auth", "bearer", "cookie", "credential", "secret", "session", "storage", "token", "key", "signature"} {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

func inspectJSONShape(raw string, depth int) OutboundState {
	trimmed := strings.TrimSpace(raw)
	if !isJSONObjectOrArray(trimmed) {
		return OutboundClean
	}
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	state, err := inspectJSONValue(decoder, depth)
	if err != nil {
		return OutboundUnknown
	}
	rest := trimmed[decoder.InputOffset():]
	if strings.TrimSpace(rest) == "" {
		return state
	}
	if strings.HasPrefix(rest, "\n\n") {
		return state
	}
	return OutboundUnknown
}

func isJSONObjectOrArray(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	return trimmed != "" && (trimmed[0] == '{' || trimmed[0] == '[')
}

func inspectJSONValue(decoder *json.Decoder, depth int) (OutboundState, error) {
	token, err := decoder.Token()
	if err != nil {
		return OutboundUnknown, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		if value, isString := token.(string); isString {
			decision := scanOutbound(value, depth+1)
			if decision.State == OutboundRedacted {
				return OutboundRefused, nil
			}
			return decision.State, nil
		}
		return OutboundClean, nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		state := OutboundClean
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return OutboundUnknown, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return OutboundUnknown, fmt.Errorf("object key was not text")
			}
			normalized, nameState := normalizeOutboundName(key)
			if nameState == OutboundUnknown {
				state = strongerOutboundState(state, OutboundUnknown)
			}
			if _, duplicate := seen[normalized]; duplicate {
				state = strongerOutboundState(state, OutboundUnknown)
			}
			seen[normalized] = struct{}{}
			if outboundNameState(key) == OutboundRefused {
				state = OutboundRefused
			}
			child, err := inspectJSONValue(decoder, depth)
			if err != nil {
				return OutboundUnknown, err
			}
			state = strongerOutboundState(state, child)
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return OutboundUnknown, fmt.Errorf("unterminated object")
		}
		return state, nil
	case '[':
		state := OutboundClean
		for decoder.More() {
			child, err := inspectJSONValue(decoder, depth)
			if err != nil {
				return OutboundUnknown, err
			}
			state = strongerOutboundState(state, child)
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return OutboundUnknown, fmt.Errorf("unterminated array")
		}
		return state, nil
	default:
		return OutboundUnknown, fmt.Errorf("unexpected delimiter")
	}
}

func strongerOutboundState(left, right OutboundState) OutboundState {
	if left == OutboundRefused || right == OutboundRefused {
		return OutboundRefused
	}
	if left == OutboundUnknown || right == OutboundUnknown {
		return OutboundUnknown
	}
	return OutboundClean
}

func normalizeOutboundName(name string) (string, OutboundState) {
	current := strings.TrimSpace(name)
	for round := 0; round < maximumNormalizationDepth && strings.Contains(current, "%"); round++ {
		decoded, err := url.QueryUnescape(current)
		if err != nil {
			return "", OutboundUnknown
		}
		if decoded == current {
			break
		}
		current = decoded
	}
	var builder strings.Builder
	for _, char := range strings.ToLower(current) {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' {
			builder.WriteRune(char)
		} else if char != '_' && char != '-' && char != '.' && char != ' ' {
			return "", OutboundUnknown
		}
	}
	if builder.Len() == 0 {
		return "", OutboundUnknown
	}
	return builder.String(), OutboundClean
}

func outboundNameState(name string) OutboundState {
	compact, state := normalizeOutboundName(name)
	if state != OutboundClean {
		return state
	}
	for _, forbidden := range []string{
		"accesstoken", "apikey", "assertion", "authorization", "authheader", "callbackcode", "clientsecret",
		"cookie", "credential", "csrf", "cursor", "idtoken", "indexeddb", "localstorage", "navigatorcredentials",
		"opaque", "opendatabase", "password", "passwd", "privatekey", "proxyauthorization", "refreshtoken",
		"samlresponse", "secret", "sessionid", "sessionstate", "sessionstorage", "signingkey", "signature", "storage", "token",
	} {
		if strings.Contains(compact, forbidden) {
			return OutboundRefused
		}
	}
	switch compact {
	case "auth", "code", "key", "session", "sig", "state":
		return OutboundRefused
	}
	if strings.HasSuffix(compact, "token") || strings.HasSuffix(compact, "secret") || strings.HasSuffix(compact, "password") || strings.HasSuffix(compact, "credential") || strings.HasSuffix(compact, "signature") {
		return OutboundRefused
	}
	return OutboundClean
}

func safePublicField(name string) bool {
	return outboundNameState(name) == OutboundClean
}

func inspectSensitiveAssignments(raw string) OutboundState {
	for _, match := range outboundAssignmentPattern.FindAllStringSubmatch(raw, -1) {
		if len(match) > 1 {
			state := outboundNameState(match[1])
			if state != OutboundClean {
				return state
			}
		}
	}
	return OutboundClean
}

func looksLikeOpaqueCredential(raw string) bool {
	for _, candidate := range opaqueCredentialPattern.FindAllString(raw, -1) {
		lower := strings.ToLower(candidate)
		if strings.Contains(lower, "redacted") {
			continue
		}
		hasLetter, hasDigit := false, false
		for _, char := range candidate {
			hasLetter = hasLetter || char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z'
			hasDigit = hasDigit || char >= '0' && char <= '9'
		}
		if hasLetter && hasDigit {
			return true
		}
	}
	return false
}
