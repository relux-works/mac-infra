package docsanitize

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

var (
	placeholderPattern = regexp.MustCompile(`^\[[A-Z][A-Z0-9_]*_[0-9]+\]$`)
	emailPattern       = regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`)
	phonePattern       = regexp.MustCompile(`(?i)(?:(?:\+?7|8)[\t ().\-]*[0-9]{3}[\t ().\-]*[0-9]{3}[\t .\-]*[0-9]{2}[\t .\-]*[0-9]{2}|\+[1-9][0-9]{0,2}(?:[\t ().\-]*[0-9]){7,14})`)
	snilsPattern       = regexp.MustCompile(`\b[0-9]{3}[ \-]?[0-9]{3}[ \-]?[0-9]{3}[ ]?[0-9]{2}\b`)
	passportPattern    = regexp.MustCompile(`\b[0-9]{2}[ \-]?[0-9]{2}[ \-]+[0-9]{6}\b`)
	taxIDPattern       = regexp.MustCompile(`\b[0-9]{12}\b`)
	cardPattern        = regexp.MustCompile(`\b[0-9](?:[ \-]?[0-9]){12,18}\b`)
	ipv4Pattern        = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	jwtPattern         = regexp.MustCompile(`\b[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)
	addressLinePattern = regexp.MustCompile(`(?im)^[\t ]*(?:[0-9]{5,6},?[\t ]+)?(?:(?:г\.|город|ул\.|улица|проспект|пр-т|пер\.|переулок|наб\.|набережная|шоссе|street|road|avenue|st\.|ave\.)[^\r\n]{4,})$`)
)

var fieldPatterns = []struct {
	category string
	pattern  *regexp.Regexp
}{
	{"full_name", regexp.MustCompile(`(?im)^([\t ]*(?:фио(?:[\t ]+полностью)?|фамилия(?:,?[\t ]+имя(?:,?[\t ]+отчество)?)?|full[ _-]?name|first[ _-]?name|last[ _-]?name|author[ _-]?name|имя[\t ]+автора)[\t ]*[:=][\t ]*)([^\r\n]+)$`)},
	{"date_of_birth", regexp.MustCompile(`(?im)^([\t ]*(?:дата[\t ]+рождения|date[ _-]?of[ _-]?birth|dob)[\t ]*[:=][\t ]*)([^\r\n]+)$`)},
	{"address", regexp.MustCompile(`(?im)^([\t ]*(?:адрес(?:[\t ]+места[\t ]+жительства)?|почтовый[\t ]+адрес|postal[ _-]?address|home[ _-]?address)[\t ]*[:=][\t ]*)([^\r\n]+)$`)},
	{"passport", regexp.MustCompile(`(?im)^([\t ]*(?:паспорт|passport)[\t ]*[:=][\t ]*)([^\r\n]+)$`)},
	{"phone", regexp.MustCompile(`(?im)^([\t ]*(?:телефон|мобильный|phone|mobile)[\t ]*[:=][\t ]*)([^\r\n]+)$`)},
	{"email", regexp.MustCompile(`(?im)^([\t ]*(?:e-?mail|email|электронная[\t ]+почта)[\t ]*[:=][\t ]*)([^\r\n]+)$`)},
	{"snils", regexp.MustCompile(`(?im)^([\t ]*(?:снилс|snils)[\t ]*[:=][\t ]*)([^\r\n]+)$`)},
	{"tax_id", regexp.MustCompile(`(?im)^([\t ]*(?:инн|tax[ _-]?id|tin)[\t ]*[:=][\t ]*)([^\r\n]+)$`)},
	{"secret", regexp.MustCompile(`(?im)^([\t ]*(?:password|passwd|пароль|api[ _-]?key|access[ _-]?token|refresh[ _-]?token|authorization|secret)[\t ]*[:=][\t ]*)([^\r\n]+)$`)},
}

var (
	nameTokenPattern = `(?:\p{Lu}[\p{Ll}]+(?:[-'][\p{Lu}][\p{Ll}]+)?|\p{Lu}{2,})`
	fullLineName     = regexp.MustCompile(`(?m)^[\t ]*(` + nameTokenPattern + `(?:[\t ]+` + nameTokenPattern + `){2,3})[\t ]*$`)
	cellName         = regexp.MustCompile(`(?m)(^|\t|\|)[\t ]*(` + nameTokenPattern + `(?:[\t ]+` + nameTokenPattern + `){2})[\t ]*(\t|\||$)`)
	initialLineName  = regexp.MustCompile(`(?m)^[\t ]*(` + nameTokenPattern + `[\t ]+\p{Lu}\.[\t ]*\p{Lu}\.)[\t ]*$`)
	initialCellName  = regexp.MustCompile(`(?m)(^|\t|\|)[\t ]*(` + nameTokenPattern + `[\t ]+\p{Lu}\.[\t ]*\p{Lu}\.)[\t ]*(\t|\||$)`)
)

func Process(ctx context.Context, pathName string, options Options) (Result, error) {
	document, err := extractDocument(ctx, pathName, options.Limits)
	if err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(document.Text) == "" {
		return Result{}, fmt.Errorf("extractor returned no readable text; scanned or image-only documents require a separate OCR step")
	}
	text, stats, warnings := SanitizeText(document.Text, document.Format, options.CustomValues)
	warnings = append(document.Warnings, warnings...)
	warnings = uniqueStrings(warnings)
	total := 0
	for _, stat := range stats {
		total += stat.Occurrences
	}
	return Result{
		Text: text,
		Report: Report{
			SchemaVersion:  SchemaVersion,
			GeneratedAt:    time.Now().UTC(),
			SourceSHA256:   document.SourceSHA256,
			InputFormat:    document.Format,
			Extractor:      document.Extractor,
			OutputEncoding: "utf-8",
			ExtractedBytes: len(document.Text),
			SanitizedBytes: len(text),
			RedactionTotal: total,
			Redactions:     stats,
			Warnings:       warnings,
		},
	}, nil
}

func SanitizeText(text, inputFormat string, customValues []string) (string, map[string]CategoryStats, []string) {
	redactor := newRedactor()
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	text = strings.ReplaceAll(text, "\u2028", "\n")
	text = strings.ReplaceAll(text, "\u2029", "\n")
	text = redactCustomValues(text, customValues, redactor)
	warnings := make([]string, 0)
	if strings.EqualFold(inputFormat, "json") {
		structured, ok := redactJSON(text, redactor)
		if ok {
			text = structured
		} else {
			warnings = append(warnings, "JSON parsing failed; content was sanitized as plain text")
		}
	}
	text = redactTSVTables(text, redactor)
	text = redactMarkdownTables(text, redactor)
	for _, field := range fieldPatterns {
		text = replaceCapture(text, field.pattern, 2, field.category, redactor, nil)
	}
	text = replacePattern(text, emailPattern, "email", redactor, nil)
	text = replacePattern(text, jwtPattern, "secret", redactor, nil)
	text = replacePattern(text, phonePattern, "phone", redactor, validPhone)
	text = replacePattern(text, snilsPattern, "snils", redactor, nil)
	text = replacePattern(text, passportPattern, "passport", redactor, nil)
	text = replacePattern(text, taxIDPattern, "tax_id", redactor, nil)
	text = replacePattern(text, cardPattern, "payment_card", redactor, validPaymentCard)
	text = replacePattern(text, ipv4Pattern, "ip_address", redactor, validIPv4)
	text = replacePattern(text, addressLinePattern, "address", redactor, nil)
	text = replaceCapture(text, fullLineName, 1, "full_name", redactor, nil)
	text = replaceCapture(text, cellName, 2, "full_name", redactor, nil)
	text = replaceCapture(text, initialLineName, 1, "full_name", redactor, nil)
	text = replaceCapture(text, initialCellName, 2, "full_name", redactor, nil)
	warnings = append(warnings, "heuristic redaction can miss uncommon identifiers or context-only personal data; review sanitized output before external disclosure")
	return text, redactor.statsSnapshot(), warnings
}

type redactor struct {
	values map[string]map[string]string
	stats  map[string]*CategoryStats
}

func newRedactor() *redactor {
	return &redactor{
		values: make(map[string]map[string]string),
		stats:  make(map[string]*CategoryStats),
	}
}

func (r *redactor) replace(category, value string) string {
	return r.replaceCount(category, value, 1)
}

func (r *redactor) replaceCount(category, value string, occurrences int) string {
	value = strings.TrimSpace(value)
	if occurrences <= 0 || blankValue(value) || placeholderPattern.MatchString(value) {
		return value
	}
	canonical := canonicalValue(category, value)
	categoryValues := r.values[category]
	if categoryValues == nil {
		categoryValues = make(map[string]string)
		r.values[category] = categoryValues
	}
	placeholder := categoryValues[canonical]
	if placeholder == "" {
		placeholder = fmt.Sprintf("[%s_%d]", strings.ToUpper(category), len(categoryValues)+1)
		categoryValues[canonical] = placeholder
	}
	stat := r.stats[category]
	if stat == nil {
		stat = &CategoryStats{}
		r.stats[category] = stat
	}
	stat.Occurrences += occurrences
	stat.Unique = len(categoryValues)
	return placeholder
}

func (r *redactor) statsSnapshot() map[string]CategoryStats {
	result := make(map[string]CategoryStats, len(r.stats))
	for category, stats := range r.stats {
		result[category] = *stats
	}
	return result
}

func canonicalValue(category, value string) string {
	value = strings.TrimSpace(value)
	switch category {
	case "email", "full_name", "address":
		return strings.ToLower(strings.Join(strings.Fields(value), " "))
	case "phone", "passport", "snils", "tax_id", "payment_card":
		var digits strings.Builder
		for _, character := range value {
			if unicode.IsDigit(character) {
				digits.WriteRune(character)
			}
		}
		return digits.String()
	default:
		return value
	}
}

func blankValue(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	for _, character := range value {
		if character != '_' && character != '-' && character != '.' && !unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func redactCustomValues(text string, values []string, redactor *redactor) string {
	filtered := make([]string, 0, len(values))
	seen := make(map[string]struct{})
	for _, value := range values {
		value = strings.TrimSpace(value)
		if blankValue(value) {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		filtered = append(filtered, value)
	}
	sort.Slice(filtered, func(i, j int) bool { return len(filtered[i]) > len(filtered[j]) })
	for _, value := range filtered {
		count := strings.Count(text, value)
		if count == 0 {
			continue
		}
		placeholder := redactor.replaceCount("custom", value, count)
		text = strings.ReplaceAll(text, value, placeholder)
	}
	return text
}

func redactJSON(text string, redactor *redactor) (string, bool) {
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return text, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return text, false
	}
	value = walkJSON(value, redactor)
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return text, false
	}
	return string(data) + "\n", true
}

func walkJSON(value any, redactor *redactor) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if category := classifySensitiveHeader(key); category != "" {
				typed[key] = redactJSONValue(category, child, redactor)
				continue
			}
			typed[key] = walkJSON(child, redactor)
		}
		return typed
	case []any:
		for index, child := range typed {
			typed[index] = walkJSON(child, redactor)
		}
		return typed
	default:
		return value
	}
}

func redactJSONValue(category string, value any, redactor *redactor) any {
	if value == nil {
		return nil
	}
	switch typed := value.(type) {
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			result[index] = redactJSONValue(category, child, redactor)
		}
		return result
	default:
		data, err := json.Marshal(value)
		if err != nil {
			return redactor.replace(category, fmt.Sprint(value))
		}
		return redactor.replace(category, string(data))
	}
}

func redactTSVTables(text string, redactor *redactor) string {
	lines := strings.Split(text, "\n")
	var sensitiveColumns map[int]string
	for lineIndex, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "# Sheet:") || strings.TrimSpace(line) == "" {
			sensitiveColumns = nil
			continue
		}
		if !strings.ContainsRune(line, '\t') {
			continue
		}
		fields := strings.Split(line, "\t")
		classified := classifyColumns(fields)
		if len(classified) > 0 {
			sensitiveColumns = classified
			continue
		}
		if len(sensitiveColumns) == 0 {
			continue
		}
		for index, category := range sensitiveColumns {
			if index < len(fields) && !blankValue(fields[index]) {
				fields[index] = redactor.replace(category, fields[index])
			}
		}
		lines[lineIndex] = strings.Join(fields, "\t")
	}
	return strings.Join(lines, "\n")
}

func redactMarkdownTables(text string, redactor *redactor) string {
	lines := strings.Split(text, "\n")
	for index := 0; index+1 < len(lines); index++ {
		headers, ok := splitMarkdownRow(lines[index])
		if !ok || !markdownSeparator(lines[index+1]) {
			continue
		}
		classified := classifyColumns(headers)
		if len(classified) == 0 {
			continue
		}
		for rowIndex := index + 2; rowIndex < len(lines); rowIndex++ {
			fields, rowOK := splitMarkdownRow(lines[rowIndex])
			if !rowOK {
				index = rowIndex - 1
				break
			}
			for column, category := range classified {
				if column < len(fields) && !blankValue(fields[column]) {
					fields[column] = redactor.replace(category, fields[column])
				}
			}
			lines[rowIndex] = "| " + strings.Join(fields, " | ") + " |"
		}
	}
	return strings.Join(lines, "\n")
}

func splitMarkdownRow(line string) ([]string, bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.Contains(trimmed, "|") {
		return nil, false
	}
	trimmed = strings.TrimPrefix(trimmed, "|")
	trimmed = strings.TrimSuffix(trimmed, "|")
	parts := strings.Split(trimmed, "|")
	if len(parts) < 2 {
		return nil, false
	}
	for index := range parts {
		parts[index] = strings.TrimSpace(parts[index])
	}
	return parts, true
}

func markdownSeparator(line string) bool {
	parts, ok := splitMarkdownRow(line)
	if !ok {
		return false
	}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, ":")
		if len(part) < 3 || strings.Trim(part, "-") != "" {
			return false
		}
	}
	return true
}

func classifyColumns(fields []string) map[int]string {
	result := make(map[int]string)
	for index, field := range fields {
		if category := classifySensitiveHeader(field); category != "" {
			result[index] = category
		}
	}
	return result
}

func classifySensitiveHeader(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.NewReplacer("_", " ", "-", " ", ".", " ", "/", " ", "(", " ", ")", " ").Replace(normalized)
	normalized = strings.Join(strings.Fields(normalized), " ")
	if normalized == "" {
		return ""
	}
	if strings.Contains(normalized, "контактн") || strings.Contains(normalized, "contact data") || strings.Contains(normalized, "contact details") {
		return "contact"
	}
	if strings.Contains(normalized, "email") || strings.Contains(normalized, "e mail") || strings.Contains(normalized, "электронн") && strings.Contains(normalized, "почт") {
		return "email"
	}
	if strings.Contains(normalized, "телефон") || strings.Contains(normalized, "мобильн") || normalized == "phone" || normalized == "mobile" || normalized == "phone number" {
		return "phone"
	}
	if strings.Contains(normalized, "адрес") || strings.Contains(normalized, "address") {
		return "address"
	}
	if strings.Contains(normalized, "дата рождения") || strings.Contains(normalized, "date of birth") || normalized == "dob" || normalized == "birth date" {
		return "date_of_birth"
	}
	if strings.Contains(normalized, "паспорт") || strings.Contains(normalized, "passport") {
		return "passport"
	}
	if strings.Contains(normalized, "снилс") || normalized == "snils" {
		return "snils"
	}
	if normalized == "инн" || normalized == "tax id" || normalized == "tin" || strings.Contains(normalized, "taxpayer id") {
		return "tax_id"
	}
	if normalized == "фио" || normalized == "фио полностью" || strings.Contains(normalized, "фамилия") || normalized == "name" || normalized == "full name" || normalized == "first name" || normalized == "last name" || normalized == "middle name" || normalized == "author" || normalized == "author name" || normalized == "автор" || normalized == "имя автора" || normalized == "фио автора" {
		return "full_name"
	}
	if strings.Contains(normalized, "password") || strings.Contains(normalized, "пароль") || strings.Contains(normalized, "api key") || strings.Contains(normalized, "access token") || strings.Contains(normalized, "refresh token") || normalized == "secret" || normalized == "authorization" {
		return "secret"
	}
	return ""
}

func replacePattern(text string, pattern *regexp.Regexp, category string, redactor *redactor, validator func(string) bool) string {
	return pattern.ReplaceAllStringFunc(text, func(match string) string {
		if validator != nil && !validator(match) {
			return match
		}
		return redactor.replace(category, match)
	})
}

func replaceCapture(text string, pattern *regexp.Regexp, group int, category string, redactor *redactor, validator func(string) bool) string {
	matches := pattern.FindAllStringSubmatchIndex(text, -1)
	if len(matches) == 0 {
		return text
	}
	var output strings.Builder
	last := 0
	for _, match := range matches {
		position := group * 2
		if position+1 >= len(match) || match[position] < 0 {
			continue
		}
		start, end := match[position], match[position+1]
		value := text[start:end]
		if validator != nil && !validator(value) {
			continue
		}
		if blankValue(value) || placeholderPattern.MatchString(strings.TrimSpace(value)) {
			continue
		}
		output.WriteString(text[last:start])
		output.WriteString(redactor.replace(category, value))
		last = end
	}
	if last == 0 {
		return text
	}
	output.WriteString(text[last:])
	return output.String()
}

func validPaymentCard(value string) bool {
	digits := make([]int, 0, len(value))
	for _, character := range value {
		if character >= '0' && character <= '9' {
			digits = append(digits, int(character-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	parity := len(digits) % 2
	for index, digit := range digits {
		if index%2 == parity {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
	}
	return sum%10 == 0
}

func validPhone(value string) bool {
	digits := 0
	for _, character := range value {
		if character >= '0' && character <= '9' {
			digits++
		}
	}
	return digits >= 10 && digits <= 15
}

func validIPv4(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 3 {
			return false
		}
		number := 0
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
			number = number*10 + int(character-'0')
		}
		if number > 255 {
			return false
		}
	}
	return true
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
