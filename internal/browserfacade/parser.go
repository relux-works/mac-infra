package browserfacade

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

type Statement struct {
	Operation string
	Args      map[string]string
	Fields    []string
}

func Parse(input string) ([]Statement, error) {
	if strings.TrimSpace(input) == "" || len(input) > maximumQueryLength {
		return nil, coded("QUERY_INVALID", "query must contain 1..%d characters", maximumQueryLength)
	}
	parts, err := splitTopLevel(input, ';')
	if err != nil {
		return nil, err
	}
	if len(parts) > maximumStatements {
		return nil, coded("QUERY_INVALID", "batch exceeds %d statements", maximumStatements)
	}
	statements := make([]Statement, 0, len(parts))
	for _, part := range parts {
		statement, err := parseStatement(part)
		if err != nil {
			return nil, err
		}
		statements = append(statements, statement)
	}
	return statements, nil
}

func parseStatement(input string) (Statement, error) {
	input = strings.TrimSpace(input)
	open := strings.IndexByte(input, '(')
	if open < 1 {
		return Statement{}, coded("QUERY_INVALID", "statement is missing operation parentheses")
	}
	operation := strings.TrimSpace(input[:open])
	if !safeNamePattern.MatchString(operation) {
		return Statement{}, coded("QUERY_INVALID", "invalid operation %q", operation)
	}
	close, err := matchingParen(input, open)
	if err != nil {
		return Statement{}, err
	}
	args, err := parseArgs(input[open+1 : close])
	if err != nil {
		return Statement{}, err
	}
	tail := strings.TrimSpace(input[close+1:])
	var fields []string
	if tail != "" {
		if len(tail) < 2 || tail[0] != '{' || tail[len(tail)-1] != '}' {
			return Statement{}, coded("QUERY_INVALID", "unexpected statement suffix")
		}
		body := strings.TrimSpace(tail[1 : len(tail)-1])
		if body == "" {
			return Statement{}, coded("QUERY_INVALID", "field projection must not be empty")
		}
		seen := map[string]bool{}
		for _, field := range strings.FieldsFunc(body, func(r rune) bool { return unicode.IsSpace(r) || r == ',' }) {
			if !fieldName(field) || seen[field] {
				return Statement{}, coded("QUERY_INVALID", "invalid or duplicate projected field %q", field)
			}
			seen[field] = true
			fields = append(fields, field)
		}
	}
	return Statement{Operation: operation, Args: args, Fields: fields}, nil
}

func matchingParen(input string, open int) (int, error) {
	quote := byte(0)
	escaped := false
	depth := 0
	for i := open; i < len(input); i++ {
		c := input[i]
		if quote != 0 {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		switch c {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i, nil
			}
		}
	}
	return 0, coded("QUERY_INVALID", "unclosed operation parentheses")
}

func parseArgs(input string) (map[string]string, error) {
	args := map[string]string{}
	if strings.TrimSpace(input) == "" {
		return args, nil
	}
	parts, err := splitTopLevel(input, ',')
	if err != nil {
		return nil, err
	}
	for _, part := range parts {
		key, raw, ok := strings.Cut(part, "=")
		key = strings.TrimSpace(key)
		if !ok || !fieldName(key) {
			return nil, coded("QUERY_INVALID", "arguments must use key=value syntax")
		}
		if _, duplicate := args[key]; duplicate {
			return nil, coded("QUERY_INVALID", "duplicate argument %q", key)
		}
		value, err := parseValue(strings.TrimSpace(raw))
		if err != nil {
			return nil, err
		}
		args[key] = value
	}
	return args, nil
}

func parseValue(raw string) (string, error) {
	if raw == "" {
		return "", coded("QUERY_INVALID", "argument value must not be empty")
	}
	if raw[0] == '\'' {
		if len(raw) < 2 || raw[len(raw)-1] != '\'' {
			return "", coded("QUERY_INVALID", "unterminated quoted argument")
		}
		return strings.ReplaceAll(raw[1:len(raw)-1], "\\'", "'"), nil
	}
	if raw[0] == '"' {
		value, err := strconv.Unquote(raw)
		if err != nil {
			return "", coded("QUERY_INVALID", "invalid quoted argument: %v", err)
		}
		return value, nil
	}
	if strings.ContainsAny(raw, "{}();,") {
		return "", coded("QUERY_INVALID", "unquoted argument contains reserved punctuation")
	}
	return raw, nil
}

func splitTopLevel(input string, separator byte) ([]string, error) {
	var parts []string
	start := 0
	quote := byte(0)
	escaped := false
	paren, braces := 0, 0
	for i := 0; i < len(input); i++ {
		c := input[i]
		if quote != 0 {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		switch c {
		case '(':
			paren++
		case ')':
			paren--
		case '{':
			braces++
		case '}':
			braces--
		}
		if paren < 0 || braces < 0 {
			return nil, coded("QUERY_INVALID", "unbalanced query delimiters")
		}
		if c == separator && paren == 0 && braces == 0 {
			part := strings.TrimSpace(input[start:i])
			if part == "" {
				return nil, coded("QUERY_INVALID", "empty statement or argument")
			}
			parts = append(parts, part)
			start = i + 1
		}
	}
	if quote != 0 || paren != 0 || braces != 0 {
		return nil, coded("QUERY_INVALID", "unbalanced query delimiters")
	}
	last := strings.TrimSpace(input[start:])
	if last == "" {
		return nil, coded("QUERY_INVALID", "empty statement or argument")
	}
	return append(parts, last), nil
}

func fieldName(value string) bool {
	if value == "" || len(value) > 48 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, r := range value[1:] {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '_' {
			return false
		}
	}
	return true
}

func requireOnlyArgs(statement Statement, allowed ...string) error {
	set := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		set[name] = true
	}
	for name := range statement.Args {
		if !set[name] {
			return coded("UNKNOWN_ARGUMENT", "%s() does not accept argument %q", statement.Operation, name)
		}
	}
	return nil
}

func intArg(args map[string]string, name string, fallback, minimum, maximum int) (int, error) {
	raw, ok := args[name]
	if !ok {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, coded("ARGUMENT_INVALID", "%s must be an integer between %d and %d", name, minimum, maximum)
	}
	return value, nil
}

func statementKey(statement Statement) string {
	keys := make([]string, 0, len(statement.Args))
	for key := range statement.Args {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var args strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&args, "%s=%s;", key, statement.Args[key])
	}
	return fmt.Sprintf("%s:%s:%s", statement.Operation, args.String(), strings.Join(statement.Fields, ","))
}
