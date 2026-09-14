package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunQProductionEntrySupportsBatchProjectionAndCompactOutput(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	bin := t.TempDir()
	writeExecutable(t, filepath.Join(bin, "mac-chrome-session"), `
if [ "$1" != "extract" ]; then exit 91; fi
printf '%s\n' '{"matched":1,"skip":0,"take":100,"returned":1,"items":[{"id":"p-1","title":"Desk lamp","price":"$20"}]}'
`)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	adapter := writeAdapter(t, home)
	var stdout, stderr bytes.Buffer
	code := run([]string{"q", "--adapter", adapter, "--format", "compact", `schema(); list(take=1) { id title }`}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	for _, want := range []string{`"operations"`, "id,title", "p-1,Desk lamp", "# returned=1"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "$20") {
		t.Fatalf("unprojected value escaped compact output: %s", stdout.String())
	}
}

func TestRunQProductionEntryDepersonalizesListStdoutCacheAndGrep(t *testing.T) {
	// This proves the public q entry depersonalizes every required PII class before both rendering and persistence, and grep sees only that cache.
	fields := []string{"id", "title", "price", "full_name", "email", "phone", "address", "date_of_birth", "passport", "snils", "tax_id", "payment_card", "ip_address"}
	query := `list(take=2) { id title price full_name email phone address date_of_birth passport snils tax_id payment_card ip_address }`
	rawValues := []string{"Иванов Иван Иванович", "alexey.petrov@example.com", "+7 (999) 123-45-67", "г. Москва, ул. Тестовая, д. 1", "01.02.1990", "45 10 123456", "112-233-445 95", "123456789012", "4111 1111 1111 1111", "192.168.10.22"}
	for _, format := range []string{"json", "compact"} {
		t.Run(format, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			bin := t.TempDir()
			writeExecutable(t, filepath.Join(bin, "mac-chrome-session"), `
printf '%s\n' '{"matched":2,"skip":0,"take":100,"returned":2,"items":[{"id":"p-1","title":"Clock Integrity","price":"$20","full_name":"Иванов Иван Иванович","email":"alexey.petrov@example.com","phone":"+7 (999) 123-45-67","address":"г. Москва, ул. Тестовая, д. 1","date_of_birth":"01.02.1990","passport":"45 10 123456","snils":"112-233-445 95","tax_id":"123456789012","payment_card":"4111 1111 1111 1111","ip_address":"192.168.10.22"},{"id":"p-2","title":"Clock Integrity","price":"$20","full_name":"Иванов Иван Иванович","email":"alexey.petrov@example.com","phone":"+7 (999) 123-45-67","address":"г. Москва, ул. Тестовая, д. 1","date_of_birth":"01.02.1990","passport":"45 10 123456","snils":"112-233-445 95","tax_id":"123456789012","payment_card":"4111 1111 1111 1111","ip_address":"192.168.10.22"}]}'
`)
			t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
			adapter := writeAdapterWithFields(t, home, fields)
			var stdout, stderr bytes.Buffer
			code := run([]string{"q", "--adapter", adapter, "--format", format, query}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			assertDepersonalized(t, stdout.Bytes(), rawValues)
			for _, want := range []string{"p-1", "p-2", "Clock Integrity", "$20", "[FULL_NAME_1]", "[EMAIL_1]", "[PHONE_1]", "[ADDRESS_1]", "[DATE_OF_BIRTH_1]", "[PASSPORT_1]", "[SNILS_1]", "[TAX_ID_1]", "[PAYMENT_CARD_1]", "[IP_ADDRESS_1]"} {
				if !strings.Contains(stdout.String(), want) {
					t.Fatalf("stdout missing %q: %s", want, stdout.String())
				}
			}
			if strings.Count(stdout.String(), "[EMAIL_1]") != 2 {
				t.Fatalf("repeated email did not receive a stable placeholder: %s", stdout.String())
			}

			cacheDirectory := filepath.Join(home, "Library", "Application Support", "mac-infra", "browser-site-cache", "marketplace")
			entries, err := os.ReadDir(cacheDirectory)
			if err != nil || len(entries) != 1 {
				t.Fatalf("cache entries=%v err=%v", entries, err)
			}
			cacheData, err := os.ReadFile(filepath.Join(cacheDirectory, entries[0].Name()))
			if err != nil {
				t.Fatal(err)
			}
			assertDepersonalized(t, cacheData, rawValues)
			if !bytes.Contains(cacheData, []byte("[EMAIL_1]")) || !bytes.Contains(cacheData, []byte("Clock Integrity")) {
				t.Fatalf("cache lost sanitized or ordinary values: %s", cacheData)
			}

			stdout.Reset()
			stderr.Reset()
			code = run([]string{"grep", "--adapter", adapter, "--format", "json", "--file", entries[0].Name(), "EMAIL_1"}, &stdout, &stderr)
			if code != 0 || !strings.Contains(stdout.String(), "[EMAIL_1]") {
				t.Fatalf("grep code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			assertDepersonalized(t, stdout.Bytes(), rawValues)
		})
	}
}

func TestRunQProductionEntryPreservesNonPIIValuesInAmbiguousFields(t *testing.T) {
	// This proves q, cache, and grep preserve ambiguous metadata unless its value contains PII, with a true-name positive control nearby.
	fields := []string{"id", "name", "addressType", "author", "fullName"}
	query := `list(take=1) { id name addressType author fullName }`
	for _, format := range []string{"json", "compact"} {
		t.Run(format, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			bin := t.TempDir()
			writeExecutable(t, filepath.Join(bin, "mac-chrome-session"), `printf '%s\n' '{"matched":1,"skip":0,"take":100,"returned":1,"items":[{"id":"p-1","name":"Desk lamp","addressType":"shipping","author":"OpenAI","fullName":"Иванов Иван Иванович"}]}'`)
			t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
			adapter := writeAdapterWithFields(t, home, fields)
			var stdout, stderr bytes.Buffer
			code := run([]string{"q", "--adapter", adapter, "--format", format, query}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("q code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			for _, want := range []string{"p-1", "Desk lamp", "shipping", "OpenAI", "[FULL_NAME_1]"} {
				if !strings.Contains(stdout.String(), want) {
					t.Fatalf("q stdout missing %q: %s", want, stdout.String())
				}
			}
			if strings.Contains(stdout.String(), "Иванов Иван Иванович") {
				t.Fatalf("q stdout retained adjacent PII: %s", stdout.String())
			}

			cacheDirectory := filepath.Join(home, "Library", "Application Support", "mac-infra", "browser-site-cache", "marketplace")
			entries, err := os.ReadDir(cacheDirectory)
			if err != nil || len(entries) != 1 {
				t.Fatalf("cache entries=%v err=%v", entries, err)
			}
			cacheData, err := os.ReadFile(filepath.Join(cacheDirectory, entries[0].Name()))
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"Desk lamp", "shipping", "OpenAI", "[FULL_NAME_1]"} {
				if !bytes.Contains(cacheData, []byte(want)) {
					t.Fatalf("cache missing %q: %s", want, cacheData)
				}
			}
			if bytes.Contains(cacheData, []byte("Иванов Иван Иванович")) {
				t.Fatalf("cache retained adjacent PII: %s", cacheData)
			}

			stdout.Reset()
			stderr.Reset()
			code = run([]string{"grep", "--adapter", adapter, "--format", format, "--file", entries[0].Name(), "OpenAI"}, &stdout, &stderr)
			if code != 0 || !strings.Contains(stdout.String(), "OpenAI") || !strings.Contains(stdout.String(), "Desk lamp") || !strings.Contains(stdout.String(), "shipping") || !strings.Contains(stdout.String(), "[FULL_NAME_1]") {
				t.Fatalf("grep code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			if strings.Contains(stdout.String(), "Иванов Иван Иванович") {
				t.Fatalf("grep stdout retained adjacent PII: %s", stdout.String())
			}
		})
	}
}

func TestRunQProductionEntryRefusesMalformedRecordWithoutOutputOrCache(t *testing.T) {
	// This proves a projected non-text record fails closed at q before stdout or cache side effects.
	home := t.TempDir()
	t.Setenv("HOME", home)
	bin := t.TempDir()
	writeExecutable(t, filepath.Join(bin, "mac-chrome-session"), `printf '%s\n' '{"matched":1,"skip":0,"take":100,"returned":1,"items":[{"id":"p-1","title":{"email":"raw@example.com"}}]}'`)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	adapter := writeAdapter(t, home)
	var stdout, stderr bytes.Buffer
	code := run([]string{"q", "--adapter", adapter, "--format", "json", `list(take=1) { id title }`}, &stdout, &stderr)
	if code == 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "TRANSPORT_RESPONSE_INVALID") || strings.Contains(stderr.String(), "raw@example.com") {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	cacheRoot := filepath.Join(home, "Library", "Application Support", "mac-infra", "browser-site-cache")
	if entries, err := os.ReadDir(cacheRoot); err == nil && len(entries) != 0 {
		t.Fatalf("malformed record reached cache: %v", entries)
	}
}

func TestRunGrepProductionEntryRefusesCacheContainingRawPII(t *testing.T) {
	// This proves grep validates depersonalization instead of treating secret-only validation as sufficient.
	home := t.TempDir()
	t.Setenv("HOME", home)
	adapter := writeAdapter(t, home)
	directory := filepath.Join(home, "Library", "Application Support", "mac-infra", "browser-site-cache", "marketplace")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "query-raw-pii.jsonl"), []byte(`{"id":"p-1","title":"alexey.petrov@example.com"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"grep", "--adapter", adapter, "--format", "json", "--file", "query-raw-pii.jsonl", "example"}, &stdout, &stderr)
	if code == 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "SENSITIVE_RESPONSE_REFUSED") || strings.Contains(stderr.String(), "alexey.petrov@example.com") {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestRunMProductionEntryRefusesAndPreviewsWithoutDispatchThenRequiresConfirm(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	marker := filepath.Join(t.TempDir(), "mutation-dispatched")
	t.Setenv("MUTATION_MARKER", marker)
	bin := t.TempDir()
	writeExecutable(t, filepath.Join(bin, "mac-chrome-session"), `
if [ "$1" != "run-js" ]; then exit 91; fi
touch "$MUTATION_MARKER"
printf '%s\n' '{"applied":true,"verification":"unknown"}'
`)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	adapter := writeAdapter(t, home)

	for name, args := range map[string][]string{
		"refusal": {"m", "--adapter", adapter, "--format", "json", `invoke(name=install)`},
		"preview": {"m", "--adapter", adapter, "--format", "json", "--dry-run", `invoke(name=install)`},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, &stdout, &stderr)
			if name == "refusal" && code == 0 {
				t.Fatalf("unguarded mutation passed: %s", stdout.String())
			}
			if name == "preview" && (code != 0 || !strings.Contains(stdout.String(), `"preview":true`)) {
				t.Fatalf("preview code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("%s dispatched browser mutation: %v", name, err)
			}
		})
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"m", "--adapter", adapter, "--format", "json", "--confirm", `invoke(name=install)`}, &stdout, &stderr); code != 0 {
		t.Fatalf("confirmed code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("confirmed mutation did not reach transport: %v", err)
	}
}

func TestRunQProductionEntryRefusesSecretResponseWithoutOutputOrCacheLeak(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	bin := t.TempDir()
	writeExecutable(t, filepath.Join(bin, "mac-chrome-session"), `
printf '%s\n' '{"matched":1,"skip":0,"take":100,"returned":1,"items":[{"id":"p-1","title":"safe","authorization":"Bearer super-secret-value"}]}'
`)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	adapter := writeAdapter(t, home)
	var stdout, stderr bytes.Buffer
	code := run([]string{"q", "--adapter", adapter, "--format", "json", `list(take=1) { id title }`}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "SENSITIVE_RESPONSE_REFUSED") {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, "super-secret-value") || strings.Contains(strings.ToLower(combined), "bearer ") {
		t.Fatalf("secret escaped refusal: %s", combined)
	}
	cacheRoot := filepath.Join(home, "Library", "Application Support", "mac-infra", "browser-site-cache")
	if entries, err := os.ReadDir(cacheRoot); err == nil && len(entries) != 0 {
		t.Fatalf("secret response reached cache: %v", entries)
	}
}

func TestRunQProductionEntryGuardsSchemaListAndCacheSecretSurfaces(t *testing.T) {
	githubToken := "ghp_012345678901234567890123456789012345"
	for name, description := range map[string]string{
		"schema-bearer":        "Install with Bearer abcdefghijklmnop",
		"schema-url":           "Install from https://shop.example/action?api_key=api-secret&signature=signed-secret",
		"schema-uppercase-url": "Install from HTTPS://SHOP.EXAMPLE/action?API_KEY=api-secret&SIGNATURE=signed-secret",
		"schema-gitlab-token":  "Install using glpat-0123456789abcdefghijklmnop",
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			adapter := writeAdapterWith(t, home, "none", 1, description)
			var stdout, stderr bytes.Buffer
			code := run([]string{"q", "--adapter", adapter, "--format", "json", `schema()`}, &stdout, &stderr)
			if code == 0 || !strings.Contains(stderr.String(), "SENSITIVE_RESPONSE_REFUSED") {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			combined := stdout.String() + stderr.String()
			for _, forbidden := range []string{"abcdefghijklmnop", "api-secret", "signed-secret"} {
				if strings.Contains(combined, forbidden) {
					t.Fatalf("schema secret escaped: %s", combined)
				}
			}
		})
	}

	t.Run("list-github-token", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		bin := t.TempDir()
		writeExecutable(t, filepath.Join(bin, "mac-chrome-session"), `
printf '%s\n' '{"matched":1,"skip":0,"take":100,"returned":1,"items":[{"id":"p-1","title":"`+githubToken+`"}]}'
`)
		t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
		adapter := writeAdapter(t, home)
		var stdout, stderr bytes.Buffer
		code := run([]string{"q", "--adapter", adapter, "--format", "json", `list(take=1) { id title }`}, &stdout, &stderr)
		if code == 0 || !strings.Contains(stderr.String(), "SENSITIVE_RESPONSE_REFUSED") || strings.Contains(stdout.String()+stderr.String(), githubToken) {
			t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
		}
		cacheRoot := filepath.Join(home, "Library", "Application Support", "mac-infra", "browser-site-cache")
		if entries, err := os.ReadDir(cacheRoot); err == nil && len(entries) != 0 {
			t.Fatalf("GitHub token reached cache: %v", entries)
		}
	})

	t.Run("list-url-redaction-and-cache", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		bin := t.TempDir()
		writeExecutable(t, filepath.Join(bin, "mac-chrome-session"), `
printf '%s\n' '{"matched":1,"skip":0,"take":100,"returned":1,"items":[{"id":"p-1","url":"https://shop.example/item?api_key=api-secret&signature=signed-secret&next=ok#opaque"}]}'
`)
		t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
		adapter := writeAdapter(t, home)
		var stdout, stderr bytes.Buffer
		code := run([]string{"q", "--adapter", adapter, "--format", "json", `list(take=1) { id url }`}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
		}
		if combined := stdout.String() + stderr.String(); strings.Contains(combined, "api-secret") || strings.Contains(combined, "signed-secret") || strings.Contains(combined, "opaque") {
			t.Fatalf("URL secret escaped: %s", combined)
		}
		cacheRoot := filepath.Join(home, "Library", "Application Support", "mac-infra", "browser-site-cache", "marketplace")
		entries, err := os.ReadDir(cacheRoot)
		if err != nil || len(entries) != 1 {
			t.Fatalf("cache entries=%v err=%v", entries, err)
		}
		data, err := os.ReadFile(filepath.Join(cacheRoot, entries[0].Name()))
		if err != nil || bytes.Contains(data, []byte("api-secret")) || bytes.Contains(data, []byte("signed-secret")) || bytes.Contains(data, []byte("opaque")) {
			t.Fatalf("cache=%s err=%v", data, err)
		}
	})

	t.Run("grep-refuses-unsanitized-cache", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		adapter := writeAdapter(t, home)
		directory := filepath.Join(home, "Library", "Application Support", "mac-infra", "browser-site-cache", "marketplace")
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "query-unsafe.jsonl"), []byte(`{"id":"p-1","title":"`+githubToken+`"}`+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := run([]string{"grep", "--adapter", adapter, "--format", "json", "lamp"}, &stdout, &stderr)
		if code == 0 || !strings.Contains(stderr.String(), "SENSITIVE_RESPONSE_REFUSED") || strings.Contains(stdout.String()+stderr.String(), githubToken) {
			t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
		}
	})
}

func TestRunQProductionEntryCentralBoundaryRejectsRepeatedVariantAttacks(t *testing.T) {
	testCases := map[string]struct {
		value    string
		wantCode string
	}{
		"uppercase-url-and-duplicate-keys": {
			value:    "HTTPS://SHOP.EXAMPLE/item?API_KEY=first-secret&api_key=second-secret&SIGNATURE=signed-secret",
			wantCode: "",
		},
		"gitlab-token": {
			value:    "glpat-0123456789abcdefghijklmnop",
			wantCode: "SENSITIVE_RESPONSE_REFUSED",
		},
		"nested-encoded-secret-url": {
			value:    "https://shop.example/redirect?next=https%253A%252F%252Fvault.example%252Fitem%253Ftoken%253Dnested-secret",
			wantCode: "SENSITIVE_RESPONSE_REFUSED",
		},
		"malformed-secret-url": {
			value:    "HTTPS://SHOP.EXAMPLE/item?API_KEY=%zz",
			wantCode: "SENSITIVE_RESPONSE_UNKNOWN",
		},
		"opaque-high-entropy-candidate": {
			value:    "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
			wantCode: "SENSITIVE_RESPONSE_UNKNOWN",
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			bin := t.TempDir()
			t.Setenv("BROWSER_VALUE", testCase.value)
			writeExecutable(t, filepath.Join(bin, "mac-chrome-session"), `
printf '%s\n' "{\"matched\":1,\"skip\":0,\"take\":100,\"returned\":1,\"items\":[{\"id\":\"p-1\",\"url\":\"$BROWSER_VALUE\"}]}"
`)
			t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
			adapter := writeAdapter(t, home)
			var stdout, stderr bytes.Buffer
			code := run([]string{"q", "--adapter", adapter, "--format", "json", `list(take=1) { id url }`}, &stdout, &stderr)
			combined := stdout.String() + stderr.String()
			for _, forbidden := range []string{"first-secret", "second-secret", "signed-secret", "glpat-", "nested-secret", "%zz", "a1b2c3d4"} {
				if strings.Contains(combined, forbidden) {
					t.Fatalf("central outbound boundary leaked %q: code=%d output=%s", forbidden, code, combined)
				}
			}
			if testCase.wantCode == "" {
				if code != 0 || !strings.Contains(stdout.String(), "redacted") {
					t.Fatalf("URL redaction code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
				}
			} else if code == 0 || !strings.Contains(stderr.String(), testCase.wantCode) {
				t.Fatalf("code=%d want=%s stdout=%s stderr=%s", code, testCase.wantCode, stdout.String(), stderr.String())
			}
			cacheRoot := filepath.Join(home, "Library", "Application Support", "mac-infra", "browser-site-cache", "marketplace")
			if entries, err := os.ReadDir(cacheRoot); err == nil {
				for _, entry := range entries {
					data, readErr := os.ReadFile(filepath.Join(cacheRoot, entry.Name()))
					if readErr != nil {
						t.Fatal(readErr)
					}
					for _, forbidden := range []string{"first-secret", "second-secret", "signed-secret", "glpat-", "nested-secret", "%zz", "a1b2c3d4"} {
						if bytes.Contains(data, []byte(forbidden)) {
							t.Fatalf("central outbound boundary leaked %q to cache: %s", forbidden, data)
						}
					}
				}
			}
		})
	}
}

func TestRunQProductionEntryRefusesRevisionFourSecretVariantsAcrossFormats(t *testing.T) {
	attacks := map[string]string{
		"nested-url-in-query-name": "https://shop.example/redirect?https%3A%2F%2Fvault.example%2Fitem%3Ftoken%3Dnested-key-secret=safe",
		"openai-project-token":     "sk-proj-0123456789abcdefghijklmnopqrstuvwxyz",
		"openai-opaque-token":      "sk-0123456789abcdefghijklmnopqrstuvwxyz",
	}
	for name, value := range attacks {
		for _, format := range []string{"compact", "json"} {
			t.Run(name+"-"+format, func(t *testing.T) {
				home := t.TempDir()
				t.Setenv("HOME", home)
				bin := t.TempDir()
				t.Setenv("BROWSER_VALUE", value)
				writeExecutable(t, filepath.Join(bin, "mac-chrome-session"), `
printf '%s\n' "{\"matched\":1,\"skip\":0,\"take\":100,\"returned\":1,\"items\":[{\"id\":\"p-1\",\"title\":\"$BROWSER_VALUE\"}]}"
`)
				t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
				adapter := writeAdapter(t, home)
				var stdout, stderr bytes.Buffer
				code := run([]string{"q", "--adapter", adapter, "--format", format, `list(take=1) { id title }`}, &stdout, &stderr)
				combined := stdout.String() + stderr.String()
				if code == 0 || !strings.Contains(stderr.String(), "SENSITIVE_RESPONSE_REFUSED") {
					t.Fatalf("attack admitted: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
				}
				for _, forbidden := range []string{"nested-key-secret", "sk-proj-", "sk-012345"} {
					if strings.Contains(combined, forbidden) {
						t.Fatalf("attack material escaped: code=%d output=%s", code, combined)
					}
				}
				cacheRoot := filepath.Join(home, "Library", "Application Support", "mac-infra", "browser-site-cache")
				if entries, err := os.ReadDir(cacheRoot); err == nil && len(entries) != 0 {
					t.Fatalf("rejected response reached cache: %v", entries)
				}
			})
		}
	}
}

func TestRunQProductionEntryRefusesSensitiveURLHostnameAndPathComponentsAcrossFormats(t *testing.T) {
	attacks := map[string]string{
		"project-token-hostname":  "https://sk-proj-0123456789abcdefghijklmnopqrstuvwxyz.example/item",
		"opaque-hostname":         "https://a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.example/item",
		"cookie-hostname":         "https://CoOkIe-State.example/item",
		"encoded-cookie-hostname": "https://%63ookie-state.example/item",
		"session-hostname":        "https://session_state.example/item",
		"storage-hostname":        "https://local-storage.example/item",
		"project-token-path":      "https://shop.example/item/sk-proj-0123456789abcdefghijklmnopqrstuvwxyz/value",
		"cookie-path":             "https://shop.example/item/CoOkIe-State/value",
		"encoded-session-path":    "https://shop.example/item/session%5Fstate/value",
		"encoded-storage-path":    "https://shop.example/item/local%2Dstorage/value",
		"bounded-session-path":    "https://shop.example/item/session%252525255Fstate/value",
	}
	for name, value := range attacks {
		for _, format := range []string{"compact", "json"} {
			t.Run(name+"-"+format, func(t *testing.T) {
				home := t.TempDir()
				t.Setenv("HOME", home)
				bin := t.TempDir()
				t.Setenv("BROWSER_VALUE", value)
				writeExecutable(t, filepath.Join(bin, "mac-chrome-session"), `
printf '%s\n' "{\"matched\":1,\"skip\":0,\"take\":100,\"returned\":1,\"items\":[{\"id\":\"p-1\",\"url\":\"$BROWSER_VALUE\"}]}"
`)
				t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
				adapter := writeAdapter(t, home)
				var stdout, stderr bytes.Buffer
				code := run([]string{"q", "--adapter", adapter, "--format", format, `list(take=1) { id url }`}, &stdout, &stderr)
				combined := stdout.String() + stderr.String()
				if code == 0 || !strings.Contains(stderr.String(), "SENSITIVE_RESPONSE_") {
					t.Fatalf("hostname/path attack admitted: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
				}
				if strings.Contains(combined, value) {
					t.Fatalf("hostname/path attack material escaped: code=%d output=%s", code, combined)
				}
				cacheRoot := filepath.Join(home, "Library", "Application Support", "mac-infra", "browser-site-cache")
				if entries, err := os.ReadDir(cacheRoot); err == nil && len(entries) != 0 {
					t.Fatalf("hostname/path attack reached cache: %v", entries)
				}
			})
		}
	}
}

func TestRunQProductionEntryGuardsCanonicalBrowserSecretNamesAcrossFormats(t *testing.T) {
	attacks := map[string]string{
		"cookie":          "https://shop.example/item?cookie=browser-cookie-value",
		"session-id":      "https://shop.example/item?session_id=opaque-session-value",
		"session-state":   "https://shop.example/item?session-state=opaque-state-value",
		"local-storage":   "https://shop.example/item?localStorage=browser-storage-value",
		"session-storage": "https://shop.example/item?session_storage=browser-storage-value",
	}
	for name, value := range attacks {
		for _, format := range []string{"compact", "json"} {
			t.Run("list-"+name+"-"+format, func(t *testing.T) {
				home := t.TempDir()
				t.Setenv("HOME", home)
				bin := t.TempDir()
				t.Setenv("BROWSER_VALUE", value)
				writeExecutable(t, filepath.Join(bin, "mac-chrome-session"), `
printf '%s\n' "{\"matched\":1,\"skip\":0,\"take\":100,\"returned\":1,\"items\":[{\"id\":\"p-1\",\"url\":\"$BROWSER_VALUE\"}]}"
`)
				t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
				adapter := writeAdapter(t, home)
				var stdout, stderr bytes.Buffer
				code := run([]string{"q", "--adapter", adapter, "--format", format, `list(take=1) { id url }`}, &stdout, &stderr)
				combined := stdout.String() + stderr.String()
				for _, forbidden := range []string{"browser-cookie-value", "opaque-session-value", "opaque-state-value", "browser-storage-value"} {
					if strings.Contains(combined, forbidden) {
						t.Fatalf("browser secret escaped: code=%d output=%s", code, combined)
					}
				}
				if code != 0 && !strings.Contains(stderr.String(), "SENSITIVE_RESPONSE_") {
					t.Fatalf("unexpected refusal: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
				}
				cacheRoot := filepath.Join(home, "Library", "Application Support", "mac-infra", "browser-site-cache", "marketplace")
				if entries, err := os.ReadDir(cacheRoot); err == nil {
					for _, entry := range entries {
						data, readErr := os.ReadFile(filepath.Join(cacheRoot, entry.Name()))
						if readErr != nil {
							t.Fatal(readErr)
						}
						for _, forbidden := range []string{"browser-cookie-value", "opaque-session-value", "opaque-state-value", "browser-storage-value"} {
							if bytes.Contains(data, []byte(forbidden)) {
								t.Fatalf("browser secret reached cache: %s", data)
							}
						}
					}
				}
			})
		}
	}

	for _, format := range []string{"compact", "json"} {
		t.Run("schema-cookie-"+format, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			adapter := writeAdapterWith(t, home, "none", 1, "Visit https://shop.example/action?cookie=schema-cookie-value")
			var stdout, stderr bytes.Buffer
			code := run([]string{"q", "--adapter", adapter, "--format", format, `schema()`}, &stdout, &stderr)
			combined := stdout.String() + stderr.String()
			if code == 0 || !strings.Contains(stderr.String(), "SENSITIVE_RESPONSE_REFUSED") || strings.Contains(combined, "schema-cookie-value") {
				t.Fatalf("schema boundary code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
		})
	}

	for _, format := range []string{"compact", "json"} {
		t.Run("schema-escaped-session-"+format, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			adapter := writeAdapterWith(t, home, "none", 1, `Visit https:\/\/shop.example\/action?session_id=escaped-schema-value`)
			var stdout, stderr bytes.Buffer
			code := run([]string{"q", "--adapter", adapter, "--format", format, `schema()`}, &stdout, &stderr)
			combined := stdout.String() + stderr.String()
			if code == 0 || !strings.Contains(stderr.String(), "SENSITIVE_RESPONSE_REFUSED") || strings.Contains(combined, "escaped-schema-value") || strings.Contains(combined, `https:\/\/`) {
				t.Fatalf("escaped schema boundary code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunQProductionEntryWithholdsEscapedTransportErrorsAcrossFormats(t *testing.T) {
	details := map[string]string{
		"json-slashes":    `transport https:\/\/shop.example\/error?callback_code=escaped-callback-value`,
		"unicode-slashes": `transport https:\u002f\u002fshop.example\u002ferror?session_state=escaped-session-value`,
		"clean-detail":    "diagnostic account detail",
	}
	for name, detail := range details {
		for _, format := range []string{"compact", "json"} {
			t.Run(name+"-"+format, func(t *testing.T) {
				home := t.TempDir()
				t.Setenv("HOME", home)
				bin := t.TempDir()
				t.Setenv("TRANSPORT_DETAIL", detail)
				writeExecutable(t, filepath.Join(bin, "mac-chrome-session"), `printf '%s\n' "$TRANSPORT_DETAIL" >&2; exit 9`)
				t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
				adapter := writeAdapter(t, home)
				var stdout, stderr bytes.Buffer
				code := run([]string{"q", "--adapter", adapter, "--format", format, `list(take=1) { id }`}, &stdout, &stderr)
				combined := stdout.String() + stderr.String()
				if code == 0 || !strings.Contains(stderr.String(), "TRANSPORT_FAILED") {
					t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
				}
				for _, forbidden := range []string{"escaped-callback-value", "escaped-session-value", "diagnostic account detail", `https:\/\/`, `https:\u002f`} {
					if strings.Contains(combined, forbidden) {
						t.Fatalf("transport detail escaped: %s", combined)
					}
				}
				cacheRoot := filepath.Join(home, "Library", "Application Support", "mac-infra", "browser-site-cache")
				if entries, err := os.ReadDir(cacheRoot); err == nil && len(entries) != 0 {
					t.Fatalf("transport refusal created cache: %v", entries)
				}
			})
		}
	}
}

func TestProductionEvidenceDecodersRejectDuplicateKeysBeforeLossyDecode(t *testing.T) {
	t.Run("extractor-items", func(t *testing.T) {
		for _, format := range []string{"compact", "json"} {
			t.Run(format, func(t *testing.T) {
				home := t.TempDir()
				t.Setenv("HOME", home)
				bin := t.TempDir()
				writeExecutable(t, filepath.Join(bin, "mac-chrome-session"), `printf '%s\n' '{"matched":1,"skip":0,"take":100,"returned":1,"items":[{"id":"p-1","title":"Bearer duplicate-extractor-secret","title":"safe"}]}'`)
				t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
				adapter := writeAdapter(t, home)
				var stdout, stderr bytes.Buffer
				code := run([]string{"q", "--adapter", adapter, "--format", format, `list(take=1) { id title }`}, &stdout, &stderr)
				combined := stdout.String() + stderr.String()
				if code == 0 || (!strings.Contains(stderr.String(), "SENSITIVE_RESPONSE_REFUSED") && !strings.Contains(stderr.String(), "SENSITIVE_RESPONSE_UNKNOWN") && !strings.Contains(stderr.String(), "TRANSPORT_RESPONSE_INVALID")) {
					t.Fatalf("duplicate extractor evidence admitted: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
				}
				if strings.Contains(combined, "duplicate-extractor-secret") || strings.Contains(stdout.String(), "safe") {
					t.Fatalf("duplicate extractor evidence escaped: %s", combined)
				}
				cacheRoot := filepath.Join(home, "Library", "Application Support", "mac-infra", "browser-site-cache")
				if entries, err := os.ReadDir(cacheRoot); err == nil && len(entries) != 0 {
					t.Fatalf("ambiguous extractor response reached cache: %v", entries)
				}
			})
		}
	})

	t.Run("pagination-advance", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		bin := t.TempDir()
		writeExecutable(t, filepath.Join(bin, "mac-chrome-session"), `
if [ "$1" = "extract" ]; then
  printf '%s\n' '{"matched":1,"skip":0,"take":100,"returned":1,"items":[{"id":"p-1"}]}'
else
  printf '%s\n' '{"advanced":false,"advanced":true}'
fi
`)
		t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
		adapter := writeAdapterWith(t, home, "next-page", 2, "Install the selected marketplace item")
		var stdout, stderr bytes.Buffer
		code := run([]string{"q", "--adapter", adapter, "--format", "json", `list(take=10) { id }`}, &stdout, &stderr)
		if code == 0 || (!strings.Contains(stderr.String(), "SENSITIVE_RESPONSE_UNKNOWN") && !strings.Contains(stderr.String(), "TRANSPORT_RESPONSE_INVALID")) {
			t.Fatalf("duplicate advance evidence admitted: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
		}
	})

	t.Run("mutation-attestation", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		bin := t.TempDir()
		writeExecutable(t, filepath.Join(bin, "mac-chrome-session"), `printf '%s\n' '{"applied":false,"applied":true,"verification":"unknown"}'`)
		t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
		adapter := writeAdapter(t, home)
		var stdout, stderr bytes.Buffer
		code := run([]string{"m", "--adapter", adapter, "--format", "json", "--confirm", `invoke(name=install)`}, &stdout, &stderr)
		if code == 0 || (!strings.Contains(stderr.String(), "SENSITIVE_RESPONSE_UNKNOWN") && !strings.Contains(stderr.String(), "TRANSPORT_RESPONSE_INVALID")) {
			t.Fatalf("duplicate mutation evidence admitted: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
		}
	})
}

func TestRunGrepProductionEntryRefusesAncestorSymlinkScopeEscape(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	adapter := writeAdapter(t, home)
	external := t.TempDir()
	externalMacInfra := filepath.Join(external, "mac-infra")
	externalSite := filepath.Join(externalMacInfra, "browser-site-cache", "marketplace")
	if err := os.MkdirAll(externalSite, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(externalSite, "query-outside.jsonl"), []byte(`{"id":"outside","title":"external escape marker"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	applicationSupport := filepath.Join(home, "Library", "Application Support")
	if err := os.MkdirAll(applicationSupport, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(externalMacInfra, filepath.Join(applicationSupport, "mac-infra")); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"grep", "--adapter", adapter, "--format", "compact", "escape marker"}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "CACHE_SCOPE_REFUSED") || strings.Contains(stdout.String()+stderr.String(), "external escape marker") {
		t.Fatalf("ancestor symlink scope escape admitted: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestRunGrepProductionEntryRefusesExplicitFinalCacheSymlinkAcrossFormats(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	adapter := writeAdapter(t, home)
	cacheDirectory := filepath.Join(home, "Library", "Application Support", "mac-infra", "browser-site-cache", "marketplace")
	if err := os.MkdirAll(cacheDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "external.jsonl")
	externalContents := []byte(`{"id":"outside","title":"external final symlink marker"}` + "\n")
	if err := os.WriteFile(external, externalContents, 0o600); err != nil {
		t.Fatal(err)
	}
	linkName := "query-final-link.jsonl"
	link := filepath.Join(cacheDirectory, linkName)
	if err := os.Symlink(external, link); err != nil {
		t.Fatal(err)
	}

	for _, format := range []string{"compact", "json"} {
		t.Run(format, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run([]string{"grep", "--adapter", adapter, "--format", format, "--file", linkName, "final symlink marker"}, &stdout, &stderr)
			combined := stdout.String() + stderr.String()
			if code == 0 || !strings.Contains(stderr.String(), "CACHE_SCOPE_REFUSED") {
				t.Fatalf("explicit final symlink was not refused: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			if strings.Contains(combined, "external final symlink marker") || strings.Contains(combined, external) {
				t.Fatalf("external cache material escaped: stdout=%s stderr=%s", stdout.String(), stderr.String())
			}
			contents, err := os.ReadFile(external)
			if err != nil || !bytes.Equal(contents, externalContents) {
				t.Fatalf("external file changed: contents=%q err=%v", contents, err)
			}
			info, err := os.Lstat(link)
			if err != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("cache symlink changed: info=%v err=%v", info, err)
			}
		})
	}
}

func TestRunGrepProductionEntryRejectsDuplicateKeyShadowing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	adapter := writeAdapter(t, home)
	directory := filepath.Join(home, "Library", "Application Support", "mac-infra", "browser-site-cache", "marketplace")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	line := `{"title":"Bearer duplicate-shadow-secret","title":"safe lamp"}` + "\n"
	if err := os.WriteFile(filepath.Join(directory, "query-duplicate.jsonl"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"grep", "--adapter", adapter, "--format", "json", "lamp"}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "SENSITIVE_RESPONSE_REFUSED") {
		t.Fatalf("duplicate-key attack code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "duplicate-shadow-secret") {
		t.Fatalf("duplicate-key secret escaped: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestFailProductionEntryAppliesCentralOutboundBoundary(t *testing.T) {
	var stderr bytes.Buffer
	code := fail(&stderr, browserfacadeError("ATTACK", "Bearer fail-boundary-secret"), 1)
	if code != 1 || strings.Contains(stderr.String(), "fail-boundary-secret") || !strings.Contains(stderr.String(), "SENSITIVE_RESPONSE_REFUSED") {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
}

func TestRunQProductionEntrySanitizesTransportErrors(t *testing.T) {
	for name, detail := range map[string]string{
		"bearer":        "Bearer abcdefghijklmnop",
		"github-token":  "ghp_012345678901234567890123456789012345",
		"gitlab-token":  "glpat-0123456789abcdefghijklmnop",
		"secret-url":    "https://shop.example/error?api_key=api-secret&signature=signed-secret#opaque",
		"uppercase-url": "HTTPS://SHOP.EXAMPLE/error?API_KEY=api-secret&SIGNATURE=signed-secret#opaque",
		"nested-url":    "https://shop.example/error?next=https%253A%252F%252Fvault.example%252Fitem%253Ftoken%253Dnested-secret",
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			bin := t.TempDir()
			t.Setenv("TRANSPORT_DETAIL", detail)
			writeExecutable(t, filepath.Join(bin, "mac-chrome-session"), `printf '%s\n' "$TRANSPORT_DETAIL" >&2; exit 9`)
			t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
			adapter := writeAdapter(t, home)
			var stdout, stderr bytes.Buffer
			code := run([]string{"q", "--adapter", adapter, "--format", "json", `list(take=1) { id }`}, &stdout, &stderr)
			if code == 0 || !strings.Contains(stderr.String(), "TRANSPORT_FAILED") {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			combined := stdout.String() + stderr.String()
			for _, forbidden := range []string{"abcdefghijklmnop", "ghp_", "glpat-", "api-secret", "signed-secret", "nested-secret", "opaque"} {
				if strings.Contains(combined, forbidden) {
					t.Fatalf("transport secret escaped: %s", combined)
				}
			}
		})
	}
}

func TestRunQProductionEntryRefusesPartialExtractorEnvelope(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	bin := t.TempDir()
	writeExecutable(t, filepath.Join(bin, "mac-chrome-session"), `printf '%s\n' '{"skip":0,"take":100}'`)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	adapter := writeAdapter(t, home)
	var stdout, stderr bytes.Buffer
	code := run([]string{"q", "--adapter", adapter, "--format", "json", `list(take=1) { id }`}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "TRANSPORT_RESPONSE_INVALID") || strings.Contains(stdout.String(), `"hasMore":false`) {
		t.Fatalf("partial extractor read became absence: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestRunQProductionEntryReportsUnknownForIndeterminatePagination(t *testing.T) {
	for name, testCase := range map[string]struct {
		maxPages int
		query    string
		advance  string
		secondID string
		wantCode int
	}{
		"duplicate-page":      {3, `list(take=10,max_pages=3) { id }`, `{"advanced":true}`, "p-1", 0},
		"caller-bound":        {3, `list(take=10,max_pages=1) { id }`, `{"advanced":true}`, "p-2", 0},
		"adapter-bound":       {2, `list(take=10) { id }`, `{"advanced":true}`, "p-2", 0},
		"partial-advance":     {2, `list(take=10) { id }`, `{}`, "p-2", 1},
		"explicit-exhaustion": {2, `list(take=10) { id }`, `{"advanced":false}`, "p-2", 0},
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			bin := t.TempDir()
			t.Setenv("ADVANCE_RESPONSE", testCase.advance)
			t.Setenv("SECOND_ID", testCase.secondID)
			t.Setenv("EXTRACT_MARKER", filepath.Join(t.TempDir(), "extracted"))
			writeExecutable(t, filepath.Join(bin, "mac-chrome-session"), `
if [ "$1" = "extract" ]; then
	if [ -f "$EXTRACT_MARKER" ]; then
	  ITEM_ID="$SECOND_ID"
	else
	  ITEM_ID="p-1"
	  touch "$EXTRACT_MARKER"
	fi
	printf '%s\n' "{\"matched\":1,\"skip\":0,\"take\":100,\"returned\":1,\"items\":[{\"id\":\"$ITEM_ID\"}]}"
else
  printf '%s\n' "$ADVANCE_RESPONSE"
fi
`)
			t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
			adapter := writeAdapterWith(t, home, "next-page", testCase.maxPages, "Install the selected marketplace item")
			var stdout, stderr bytes.Buffer
			code := run([]string{"q", "--adapter", adapter, "--format", "json", testCase.query}, &stdout, &stderr)
			if code != testCase.wantCode {
				t.Fatalf("code=%d want=%d stdout=%s stderr=%s", code, testCase.wantCode, stdout.String(), stderr.String())
			}
			if name == "partial-advance" {
				if !strings.Contains(stderr.String(), "TRANSPORT_RESPONSE_INVALID") || strings.Contains(stdout.String(), `"hasMore":false`) {
					t.Fatalf("partial read became absence: stdout=%s stderr=%s", stdout.String(), stderr.String())
				}
				return
			}
			want := `"hasMore":"unknown"`
			if name == "explicit-exhaustion" {
				want = `"hasMore":"false"`
			}
			if !strings.Contains(stdout.String(), want) {
				t.Fatalf("stdout=%s want=%s", stdout.String(), want)
			}
		})
	}
}

func TestRunGrepProductionEntryUsesOnlyCacheAndNeverBrowserTransport(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "browser-called")
	t.Setenv("BROWSER_MARKER", marker)
	writeExecutable(t, filepath.Join(bin, "mac-chrome-session"), `touch "$BROWSER_MARKER"; exit 99`)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	adapter := writeAdapter(t, home)
	directory := filepath.Join(home, "Library", "Application Support", "mac-infra", "browser-site-cache", "marketplace")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "query-safe.jsonl"), []byte(`{"id":"p-1","title":"Desk lamp"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"grep", "--adapter", adapter, "--format", "compact", "lamp"}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "Desk lamp") {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("grep reached browser transport: %v", err)
	}
}

func TestUsageNamesSeparateQGrepMContracts(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d", code)
	}
	for _, want := range []string{" q ", " grep ", " m ", "--dry-run", "--confirm", "per-site"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("usage missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestRunVersionUnknownAndArgumentRefusals(t *testing.T) {
	for name, args := range map[string][]string{
		"no-args":        {},
		"unknown":        {"nope"},
		"query-args":     {"q", "--format", "yaml"},
		"grep-args":      {"grep", "--format", "json"},
		"mutation-flags": {"m", "--adapter", "missing.json", "--format", "json", "--dry-run", "--confirm", `invoke(name=x)`},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code == 0 {
				t.Fatalf("invalid invocation passed: stdout=%s", stdout.String())
			}
		})
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "mac-browser-site") {
		t.Fatalf("version code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestRunQueryRefusesUnreadableAndInvalidAdapter(t *testing.T) {
	for name, path := range map[string]string{
		"missing": filepath.Join(t.TempDir(), "missing.json"),
		"invalid": filepath.Join(t.TempDir(), "invalid.json"),
	} {
		t.Run(name, func(t *testing.T) {
			if name == "invalid" {
				if err := os.WriteFile(path, []byte(`{"unknown":true}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var stdout, stderr bytes.Buffer
			if code := run([]string{"q", "--adapter", path, "--format", "json", `schema()`}, &stdout, &stderr); code == 0 {
				t.Fatalf("adapter passed: %s", stdout.String())
			}
			if !strings.Contains(stderr.String(), "ADAPTER_INVALID") {
				t.Fatalf("stderr=%s", stderr.String())
			}
		})
	}
}

func writeAdapter(t *testing.T, directory string) string {
	return writeAdapterWith(t, directory, "none", 1, "Install the selected marketplace item")
}

func writeAdapterWith(t *testing.T, directory, paginationKind string, maxPages int, description string) string {
	t.Helper()
	adapter := map[string]any{
		"name":    "marketplace",
		"browser": "chrome",
		"target":  map[string]any{"browser": "chrome", "windowId": "11", "tabId": "22", "origin": "https://shop.example"},
		"template": map[string]any{
			"itemSelector": ".item",
			"fields": map[string]any{
				"id":    map[string]any{"source": "attribute", "attribute": "aria-label"},
				"title": map[string]any{"source": "text"},
				"price": map[string]any{"source": "text"},
				"url":   map[string]any{"source": "text"},
			},
		},
		"pagination": map[string]any{"kind": paginationKind, "maxPages": maxPages},
		"mutations": map[string]any{
			"install": map[string]any{"description": description, "selector": "button.install", "destructive": false},
		},
	}
	if paginationKind == "next-page" || paginationKind == "cursor" {
		adapter["pagination"].(map[string]any)["selector"] = "button.next"
	}
	data, err := json.Marshal(adapter)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "adapter.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeAdapterWithFields(t *testing.T, directory string, fields []string) string {
	t.Helper()
	path := writeAdapter(t, directory)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var adapter map[string]any
	if err := json.Unmarshal(data, &adapter); err != nil {
		t.Fatal(err)
	}
	definitions := make(map[string]any, len(fields))
	for _, field := range fields {
		definitions[field] = map[string]any{"source": "text"}
	}
	adapter["template"].(map[string]any)["fields"] = definitions
	data, err = json.Marshal(adapter)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertDepersonalized(t *testing.T, data []byte, rawValues []string) {
	t.Helper()
	for _, raw := range rawValues {
		if bytes.Contains(data, []byte(raw)) {
			t.Fatalf("personal data %q escaped: %s", raw, data)
		}
	}
}

func writeExecutable(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
}
