package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/relux-works/mac-infra/internal/docsanitize"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

type pathFlags []string

func (f *pathFlags) String() string {
	return strings.Join(*f, ",")
}

func (f *pathFlags) Set(value string) error {
	*f = append(*f, value)
	return nil
}

type commandSummary struct {
	OK                   bool   `json:"ok"`
	SanitizedPath        string `json:"sanitized_path"`
	ReportPath           string `json:"report_path,omitempty"`
	InputFormat          string `json:"input_format"`
	SourceSHA256         string `json:"source_sha256"`
	RedactionOccurrences int    `json:"redaction_occurrences"`
	WarningCount         int    `json:"warning_count"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stdout)
		return 2
	}
	switch args[0] {
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	case "version":
		fmt.Fprintf(stdout, "mac-document-sanitize %s %s %s\n", Version, Commit, BuildDate)
		return 0
	}

	flags := flag.NewFlagSet("mac-document-sanitize", flag.ContinueOnError)
	flags.SetOutput(stderr)
	outputPath := flags.String("out", "", "sanitized UTF-8 text output path")
	reportPath := flags.String("report", "", "redaction report JSON output path")
	artifactDir := flags.String("artifact-dir", filepath.Join(".temp", "mac-document-sanitize"), "default artifact directory")
	noReport := flags.Bool("no-report", false, "do not write a JSON redaction report")
	jsonOutput := flags.Bool("json", false, "print a machine-readable command summary")
	maxInputMB := flags.Int64("max-input-mb", 50, "maximum source file size in MiB")
	maxExtractedMB := flags.Int64("max-extracted-mb", 20, "maximum extracted text size in MiB")
	timeout := flags.Duration("timeout", 2*time.Minute, "maximum extraction and sanitization time")
	var redactFrom pathFlags
	flags.Var(&redactFrom, "redact-from", "0600 text file with additional exact values to redact; repeatable")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if len(flags.Args()) != 1 {
		fmt.Fprintln(stderr, "exactly one input document is required")
		return 2
	}
	if *maxInputMB <= 0 || *maxExtractedMB <= 0 {
		fmt.Fprintln(stderr, "size limits must be positive")
		return 2
	}
	if *timeout <= 0 {
		fmt.Fprintln(stderr, "timeout must be positive")
		return 2
	}
	if *noReport && strings.TrimSpace(*reportPath) != "" {
		fmt.Fprintln(stderr, "--report cannot be combined with --no-report")
		return 2
	}

	inputPath := flags.Args()[0]
	customValues, err := readCustomValues(redactFrom)
	if err != nil {
		fmt.Fprintf(stderr, "read custom redactions: %s\n", safeError(err, redactFrom...))
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result, err := docsanitize.Process(ctx, inputPath, docsanitize.Options{
		Limits: docsanitize.Limits{
			MaxInputBytes:     *maxInputMB << 20,
			MaxExtractedBytes: *maxExtractedMB << 20,
		},
		CustomValues: customValues,
	})
	if err != nil {
		fmt.Fprintf(stderr, "sanitize failed: %s\n", safeError(err, inputPath))
		return 1
	}
	defaultOutput, defaultReport, err := docsanitize.DefaultArtifactPaths(*artifactDir, result.Report.SourceSHA256)
	if err != nil {
		fmt.Fprintf(stderr, "sanitize failed: %v\n", err)
		return 1
	}
	if strings.TrimSpace(*outputPath) == "" {
		*outputPath = defaultOutput
	}
	if !*noReport && strings.TrimSpace(*reportPath) == "" {
		*reportPath = defaultReport
	}
	paths := []string{inputPath, *outputPath}
	if !*noReport {
		paths = append(paths, *reportPath)
	}
	if err := requireDistinctPaths(paths...); err != nil {
		fmt.Fprintf(stderr, "sanitize failed: %v\n", err)
		return 1
	}
	if err := docsanitize.WriteTextArtifact(*outputPath, result.Text); err != nil {
		fmt.Fprintf(stderr, "sanitize failed: write text: %v\n", err)
		return 1
	}
	if !*noReport {
		if err := docsanitize.WriteReportArtifact(*reportPath, result.Report); err != nil {
			fmt.Fprintf(stderr, "sanitize failed: write report: %v\n", err)
			return 1
		}
	}

	summary := commandSummary{
		OK:                   true,
		SanitizedPath:        *outputPath,
		InputFormat:          result.Report.InputFormat,
		SourceSHA256:         result.Report.SourceSHA256,
		RedactionOccurrences: result.Report.RedactionTotal,
		WarningCount:         len(result.Report.Warnings),
	}
	if !*noReport {
		summary.ReportPath = *reportPath
	}
	if *jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(summary); err != nil {
			fmt.Fprintf(stderr, "sanitize failed: encode summary: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "sanitized: %s\n", summary.SanitizedPath)
	if summary.ReportPath != "" {
		fmt.Fprintf(stdout, "report: %s\n", summary.ReportPath)
	}
	fmt.Fprintf(stdout, "format: %s\n", summary.InputFormat)
	fmt.Fprintf(stdout, "redactions: %d\n", summary.RedactionOccurrences)
	fmt.Fprintf(stdout, "warnings: %d\n", summary.WarningCount)
	return 0
}

func readCustomValues(paths []string) ([]string, error) {
	const maxDictionaryBytes = int64(1 << 20)
	values := make([]string, 0)
	for _, pathName := range paths {
		info, err := os.Stat(pathName)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Size() > maxDictionaryBytes {
			return nil, fmt.Errorf("custom redaction dictionary must be a regular file no larger than 1 MiB")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("custom redaction dictionary must not be readable or writable by group or other users")
		}
		file, err := os.Open(pathName)
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(io.LimitReader(file, maxDictionaryBytes+1))
		for scanner.Scan() {
			if value := strings.TrimSpace(scanner.Text()); value != "" {
				values = append(values, value)
			}
		}
		closeErr := file.Close()
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	return values, nil
}

func requireDistinctPaths(paths ...string) error {
	canonical := make([]string, 0, len(paths))
	for _, pathName := range paths {
		absolute, err := filepath.Abs(pathName)
		if err != nil {
			return err
		}
		if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
			absolute = resolved
		}
		for _, existing := range canonical {
			if absolute == existing {
				return fmt.Errorf("input, sanitized output, and report paths must be different")
			}
		}
		canonical = append(canonical, absolute)
	}
	return nil
}

func safeError(err error, sensitivePaths ...string) string {
	message := err.Error()
	replacements := make([]string, 0, len(sensitivePaths)*2)
	for _, pathName := range sensitivePaths {
		if strings.TrimSpace(pathName) == "" {
			continue
		}
		replacements = append(replacements, pathName)
		if absolute, absErr := filepath.Abs(pathName); absErr == nil {
			replacements = append(replacements, absolute)
		}
	}
	sort.Slice(replacements, func(i, j int) bool { return len(replacements[i]) > len(replacements[j]) })
	for _, pathName := range replacements {
		message = strings.ReplaceAll(message, pathName, "[INPUT]")
	}
	return message
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: mac-document-sanitize [options] INPUT")
	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "Creates a sanitized UTF-8 text copy and non-sensitive redaction report.")
	fmt.Fprintln(writer, "The source document is read-only and raw extracted text is not persisted.")
	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "supported inputs:")
	fmt.Fprintln(writer, "  TXT, Markdown, JSON, XML, YAML, CSV, TSV")
	fmt.Fprintln(writer, "  HTML, RTF, DOC, DOCX via macOS textutil")
	fmt.Fprintln(writer, "  PDF via pdftotext (Homebrew poppler)")
	fmt.Fprintln(writer, "  XLSX via built-in OOXML extraction")
	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "options:")
	fmt.Fprintln(writer, "  --out PATH           sanitized text output")
	fmt.Fprintln(writer, "  --report PATH        redaction report JSON")
	fmt.Fprintln(writer, "  --artifact-dir PATH  default output directory")
	fmt.Fprintln(writer, "  --redact-from PATH   exact-value dictionary; repeatable")
	fmt.Fprintln(writer, "  --json               machine-readable command summary")
	fmt.Fprintln(writer, "  --no-report          skip report output")
	fmt.Fprintln(writer, "  version              print version")
}
