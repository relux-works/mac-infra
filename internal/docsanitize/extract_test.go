package docsanitize

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProcessReadsTextWithoutChangingSource(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "source.txt")
	input := "ФИО: Иванов Иван Иванович\nUseful technical description\n"
	if err := os.WriteFile(inputPath, []byte(input), 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(inputPath)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Process(context.Background(), inputPath, Options{})
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != input || before.Mode() != after.Mode() || before.ModTime() != after.ModTime() {
		t.Fatalf("source changed: before=%#v after=%#v content=%q", before, after, data)
	}
	if strings.Contains(result.Text, "Иванов Иван Иванович") || !strings.Contains(result.Text, "Useful technical description") {
		t.Fatalf("result = %q", result.Text)
	}
	if result.Report.SourceSHA256 == "" || result.Report.InputFormat != "txt" || result.Report.Extractor != "direct" {
		t.Fatalf("report = %#v", result.Report)
	}
}

func TestProcessNormalizesCSVAndRedactsSensitiveColumns(t *testing.T) {
	inputPath := filepath.Join(t.TempDir(), "authors.csv")
	input := "Full name,Email,Contribution\nJohn Smith,john@example.com,Architecture\n"
	if err := os.WriteFile(inputPath, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Process(context.Background(), inputPath, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.Text, "John Smith") || strings.Contains(result.Text, "john@example.com") {
		t.Fatalf("CSV retained personal data:\n%s", result.Text)
	}
	if !strings.Contains(result.Text, "Architecture") || result.Report.InputFormat != "csv" {
		t.Fatalf("result = %#v", result)
	}
}

func TestProcessRejectsDocumentsWithoutReadableText(t *testing.T) {
	inputPath := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(inputPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Process(context.Background(), inputPath, Options{})
	if err == nil || !strings.Contains(err.Error(), "no readable text") {
		t.Fatalf("error = %v", err)
	}
}

func TestProcessExtractsAndSanitizesXLSX(t *testing.T) {
	inputPath := filepath.Join(t.TempDir(), "authors.xlsx")
	createXLSXFixture(t, inputPath)
	result, err := Process(context.Background(), inputPath, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, sensitive := range []string{"Иванов Иван Иванович", "ivanov@example.com"} {
		if strings.Contains(result.Text, sensitive) {
			t.Fatalf("XLSX retained %q:\n%s", sensitive, result.Text)
		}
	}
	if !strings.Contains(result.Text, "Clock monitor architecture") || !strings.Contains(result.Text, "# Sheet: Authors") {
		t.Fatalf("XLSX lost semantic content:\n%s", result.Text)
	}
	if result.Report.InputFormat != "xlsx" || result.Report.Extractor != "ooxml" {
		t.Fatalf("report = %#v", result.Report)
	}
}

func TestDefaultArtifactPathsUseContentHashNotSourceName(t *testing.T) {
	textPath, reportPath, err := DefaultArtifactPaths(".temp/output", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if textPath != ".temp/output/document-aaaaaaaaaaaa.sanitized.txt" || reportPath != ".temp/output/document-aaaaaaaaaaaa.redaction.json" {
		t.Fatalf("paths = %q %q", textPath, reportPath)
	}
}

func TestWriteArtifactsUsePrivatePermissions(t *testing.T) {
	directory := t.TempDir()
	textPath := filepath.Join(directory, "sanitized.txt")
	reportPath := filepath.Join(directory, "report.json")
	if err := WriteTextArtifact(textPath, "safe\n"); err != nil {
		t.Fatal(err)
	}
	if err := WriteReportArtifact(reportPath, Report{SchemaVersion: 1, Redactions: map[string]CategoryStats{}}); err != nil {
		t.Fatal(err)
	}
	for _, pathName := range []string{textPath, reportPath} {
		info, err := os.Stat(pathName)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s mode = %o, want 600", pathName, got)
		}
	}
}

func createXLSXFixture(t *testing.T, pathName string) {
	t.Helper()
	file, err := os.Create(pathName)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(file)
	entries := map[string]string{
		"xl/workbook.xml":            `<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Authors" sheetId="1" r:id="rId1"/></sheets></workbook>`,
		"xl/_rels/workbook.xml.rels": `<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Target="worksheets/sheet1.xml" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"/></Relationships>`,
		"xl/sharedStrings.xml":       `<?xml version="1.0" encoding="UTF-8"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><si><t>ФИО</t></si><si><t>Email</t></si><si><t>Contribution</t></si><si><t>Иванов Иван Иванович</t></si><si><t>ivanov@example.com</t></si><si><t>Clock monitor architecture</t></si></sst>`,
		"xl/worksheets/sheet1.xml":   `<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="C1" t="s"><v>2</v></c></row><row r="2"><c r="A2" t="s"><v>3</v></c><c r="B2" t="s"><v>4</v></c><c r="C2" t="s"><v>5</v></c></row></sheetData></worksheet>`,
	}
	for name, content := range entries {
		writer, err := archive.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
