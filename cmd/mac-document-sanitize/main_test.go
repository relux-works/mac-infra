package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	for _, want := range []string{"mac-document-sanitize", "DOCX", "PDF", "XLSX", "--redact-from"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("help missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestRunWritesPrivateSanitizedArtifactsWithoutChangingInput(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "private-name.txt")
	outputPath := filepath.Join(directory, "out", "sanitized.txt")
	reportPath := filepath.Join(directory, "out", "report.json")
	input := "ФИО: Иванов Иван Иванович\nClock monitor architecture\n"
	if err := os.WriteFile(inputPath, []byte(input), 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"--json", "--out", outputPath, "--report", reportPath, inputPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	after, err := os.Stat(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode() != after.Mode() || before.ModTime() != after.ModTime() {
		t.Fatalf("input metadata changed: before=%#v after=%#v", before, after)
	}
	for _, pathName := range []string{outputPath, reportPath} {
		info, err := os.Stat(pathName)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o", pathName, info.Mode().Perm())
		}
	}
	output, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(output), "Иванов Иван Иванович") || !strings.Contains(string(output), "Clock monitor architecture") {
		t.Fatalf("sanitized output = %s", output)
	}
	report, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(report), "Иванов") || strings.Contains(string(report), "private-name") {
		t.Fatalf("report leaked source data: %s", report)
	}
	var summary commandSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("summary is invalid JSON: %v\n%s", err, stdout.String())
	}
	if !summary.OK || summary.RedactionOccurrences == 0 || summary.SanitizedPath != outputPath {
		t.Fatalf("summary = %#v", summary)
	}
}

func TestRunRejectsInputAsOutput(t *testing.T) {
	inputPath := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(inputPath, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"--out", inputPath, inputPath}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "must be different") {
		t.Fatalf("code = %d stdout = %s stderr = %s", code, stdout.String(), stderr.String())
	}
	data, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "safe" {
		t.Fatalf("input changed: %q", data)
	}
}

func TestRunCustomDictionaryDoesNotLeakIntoReport(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "input.txt")
	dictionaryPath := filepath.Join(directory, "dictionary.txt")
	outputPath := filepath.Join(directory, "sanitized.txt")
	reportPath := filepath.Join(directory, "report.json")
	if err := os.WriteFile(inputPath, []byte("Internal codename Falcon"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dictionaryPath, []byte("Falcon\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"--redact-from", dictionaryPath, "--out", outputPath, "--report", reportPath, inputPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d stderr = %s", code, stderr.String())
	}
	for _, pathName := range []string{outputPath, reportPath} {
		data, err := os.ReadFile(pathName)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "Falcon") {
			t.Fatalf("%s leaked custom value: %s", pathName, data)
		}
	}
}

func TestRunRejectsPublicCustomDictionary(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "input.txt")
	dictionaryPath := filepath.Join(directory, "dictionary.txt")
	if err := os.WriteFile(inputPath, []byte("Internal codename Falcon"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dictionaryPath, []byte("Falcon\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"--redact-from", dictionaryPath, inputPath}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "must not be readable") {
		t.Fatalf("code = %d stdout = %s stderr = %s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), dictionaryPath) {
		t.Fatalf("stderr leaked dictionary path: %s", stderr.String())
	}
}
