package docsanitize

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSanitizeTextRedactsCommonPersonalData(t *testing.T) {
	input := strings.Join([]string{
		"Project: Clock Integrity",
		"ФИО: Иванов Иван Иванович",
		"Email: alexey.petrov@example.com",
		"Repeat alexey.petrov@example.com",
		"Телефон: +7 (999) 123-45-67",
		"International contact +1 (415) 555-2671",
		"Паспорт: 45 10 123456",
		"СНИЛС: 112-233-445 95",
		"ИНН: 123456789012",
		"Дата рождения: 01.02.1990",
		"Адрес: г. Москва, ул. Тестовая, д. 1",
		"Card: 4111 1111 1111 1111",
		"Host: 192.168.10.22",
	}, "\n")

	output, stats, warnings := SanitizeText(input, "txt", nil)
	for _, sensitive := range []string{
		"Иванов Иван Иванович",
		"alexey.petrov@example.com",
		"+7 (999) 123-45-67",
		"+1 (415) 555-2671",
		"45 10 123456",
		"112-233-445 95",
		"123456789012",
		"01.02.1990",
		"г. Москва, ул. Тестовая, д. 1",
		"4111 1111 1111 1111",
		"192.168.10.22",
	} {
		if strings.Contains(output, sensitive) {
			t.Fatalf("sanitized text retained %q:\n%s", sensitive, output)
		}
	}
	if !strings.Contains(output, "Project: Clock Integrity") {
		t.Fatalf("semantic content was lost:\n%s", output)
	}
	if count := strings.Count(output, "[EMAIL_1]"); count != 2 {
		t.Fatalf("stable email placeholder count = %d, want 2:\n%s", count, output)
	}
	for _, category := range []string{"full_name", "email", "phone", "passport", "snils", "tax_id", "date_of_birth", "address", "payment_card", "ip_address"} {
		if stats[category].Occurrences == 0 {
			t.Fatalf("missing %s stats: %#v", category, stats)
		}
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "heuristic") {
		t.Fatalf("warnings = %#v, want heuristic warning", warnings)
	}
}

func TestSanitizeTextUsesSensitiveTSVColumns(t *testing.T) {
	input := strings.Join([]string{
		"ФИО\tТелефон\tЧто сделал автор",
		"Петров Петр Петрович\t+7 901 111-22-33\tDesigned the clock monitor",
		"Сидоров Сидор Сидорович\t+7 901 444-55-66\tValidated the prototype",
	}, "\n")

	output, stats, _ := SanitizeText(input, "xlsx", nil)
	for _, sensitive := range []string{"Петров Петр Петрович", "Сидоров Сидор Сидорович", "+7 901 111-22-33", "+7 901 444-55-66"} {
		if strings.Contains(output, sensitive) {
			t.Fatalf("table retained %q:\n%s", sensitive, output)
		}
	}
	for _, semantic := range []string{"Designed the clock monitor", "Validated the prototype"} {
		if !strings.Contains(output, semantic) {
			t.Fatalf("table lost %q:\n%s", semantic, output)
		}
	}
	if stats["full_name"].Occurrences != 2 || stats["phone"].Occurrences != 2 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestSanitizeTextUsesSensitiveMarkdownColumns(t *testing.T) {
	input := "| Full name | Email | Contribution |\n| --- | --- | --- |\n| John Smith | john@example.com | Architecture |\n"
	output, stats, _ := SanitizeText(input, "md", nil)
	if strings.Contains(output, "John Smith") || strings.Contains(output, "john@example.com") {
		t.Fatalf("markdown table retained personal data:\n%s", output)
	}
	if !strings.Contains(output, "Architecture") {
		t.Fatalf("markdown table lost semantic content:\n%s", output)
	}
	if stats["full_name"].Occurrences != 1 || stats["email"].Occurrences != 1 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestSanitizeTextUsesSensitiveJSONKeys(t *testing.T) {
	input := `{"full_name":"John Smith","email":"john@example.com","nested":{"password":"hunter2"},"project":"Clock Integrity"}`
	output, stats, _ := SanitizeText(input, "json", nil)
	for _, sensitive := range []string{"John Smith", "john@example.com", "hunter2"} {
		if strings.Contains(output, sensitive) {
			t.Fatalf("JSON retained %q:\n%s", sensitive, output)
		}
	}
	if !strings.Contains(output, "Clock Integrity") {
		t.Fatalf("JSON lost semantic content:\n%s", output)
	}
	if stats["full_name"].Occurrences != 1 || stats["email"].Occurrences != 1 || stats["secret"].Occurrences != 1 {
		t.Fatalf("stats = %#v", stats)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(output), &decoded); err != nil {
		t.Fatalf("sanitized JSON is invalid: %v\n%s", err, output)
	}
}

func TestSanitizeTextAppliesStableCustomRedactions(t *testing.T) {
	output, stats, _ := SanitizeText("Project Falcon / Falcon", "txt", []string{"Falcon"})
	if output != "Project [CUSTOM_1] / [CUSTOM_1]" {
		t.Fatalf("output = %q", output)
	}
	if stats["custom"] != (CategoryStats{Occurrences: 2, Unique: 1}) {
		t.Fatalf("custom stats = %#v", stats["custom"])
	}
}

func TestPaymentCardValidationAvoidsArbitraryLongNumber(t *testing.T) {
	output, stats, _ := SanitizeText("valid 4111111111111111 invalid 4111111111111112", "txt", nil)
	if !strings.Contains(output, "[PAYMENT_CARD_1]") || !strings.Contains(output, "4111111111111112") {
		t.Fatalf("output = %q", output)
	}
	if stats["payment_card"].Occurrences != 1 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestRussianPhoneWinsOverSNILSPattern(t *testing.T) {
	output, stats, _ := SanitizeText("Contact: +7 916 123-45-67", "txt", nil)
	if output != "Contact: [PHONE_1]" {
		t.Fatalf("output = %q", output)
	}
	if stats["phone"].Occurrences != 1 || stats["snils"].Occurrences != 0 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestUnicodeLineSeparatorDoesNotExtendSensitiveField(t *testing.T) {
	output, _, _ := SanitizeText("Email: john@example.com\u2028Project: Clock Integrity", "docx", nil)
	if strings.Contains(output, "john@example.com") || !strings.Contains(output, "Project: Clock Integrity") {
		t.Fatalf("output = %q", output)
	}
}
