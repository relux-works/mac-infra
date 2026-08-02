package docsanitize

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

func extractDocument(ctx context.Context, pathName string, limits Limits) (extractedDocument, error) {
	limits = normalizeLimits(limits)
	info, err := os.Stat(pathName)
	if err != nil {
		return extractedDocument{}, fmt.Errorf("inspect input: %w", err)
	}
	if !info.Mode().IsRegular() {
		return extractedDocument{}, fmt.Errorf("input must be a regular file")
	}
	if info.Size() > limits.MaxInputBytes {
		return extractedDocument{}, fmt.Errorf("input is %d bytes; limit is %d", info.Size(), limits.MaxInputBytes)
	}
	sourceHash, err := hashFile(pathName, limits.MaxInputBytes)
	if err != nil {
		return extractedDocument{}, err
	}

	extension := strings.ToLower(filepath.Ext(pathName))
	result := extractedDocument{SourceSHA256: sourceHash}
	switch extension {
	case ".txt", ".md", ".markdown", ".json", ".xml", ".yaml", ".yml":
		data, err := readFileLimited(pathName, limits.MaxExtractedBytes)
		if err != nil {
			return extractedDocument{}, err
		}
		if utf8.Valid(data) && !bytes.ContainsRune(data, '\x00') {
			result.Text = string(data)
			result.Format = strings.TrimPrefix(extension, ".")
			result.Extractor = "direct"
			return result, nil
		}
		data, err = extractWithTextutil(ctx, pathName, limits.MaxExtractedBytes)
		if err != nil {
			return extractedDocument{}, fmt.Errorf("input is not valid UTF-8 and textutil conversion failed: %w", err)
		}
		result.Text = string(data)
		result.Format = strings.TrimPrefix(extension, ".")
		result.Extractor = "textutil"
		result.Warnings = append(result.Warnings, "source text was transcoded to UTF-8 with textutil")
		return result, nil
	case ".csv", ".tsv":
		data, err := readFileLimited(pathName, limits.MaxExtractedBytes)
		if err != nil {
			return extractedDocument{}, err
		}
		if !utf8.Valid(data) {
			data, err = extractWithTextutil(ctx, pathName, limits.MaxExtractedBytes)
			if err != nil {
				return extractedDocument{}, fmt.Errorf("table text is not valid UTF-8 and textutil conversion failed: %w", err)
			}
			result.Warnings = append(result.Warnings, "table text was transcoded to UTF-8 with textutil")
		}
		delimiter := ','
		if extension == ".tsv" {
			delimiter = '\t'
		}
		normalized, warning := normalizeDelimitedText(string(data), delimiter, limits.MaxExtractedBytes)
		if warning != "" {
			result.Warnings = append(result.Warnings, warning)
		}
		result.Text = normalized
		result.Format = strings.TrimPrefix(extension, ".")
		result.Extractor = "delimited-text"
		return result, nil
	case ".html", ".htm", ".rtf", ".doc", ".docx":
		data, err := extractWithTextutil(ctx, pathName, limits.MaxExtractedBytes)
		if err != nil {
			return extractedDocument{}, err
		}
		result.Text = string(data)
		result.Format = strings.TrimPrefix(extension, ".")
		result.Extractor = "textutil"
		return result, nil
	case ".pdf":
		data, err := extractPDF(ctx, pathName, limits.MaxExtractedBytes)
		if err != nil {
			return extractedDocument{}, err
		}
		result.Text = string(data)
		result.Format = "pdf"
		result.Extractor = "pdftotext"
		return result, nil
	case ".xlsx":
		text, warnings, err := extractXLSX(pathName, limits.MaxExtractedBytes)
		if err != nil {
			return extractedDocument{}, err
		}
		result.Text = text
		result.Format = "xlsx"
		result.Extractor = "ooxml"
		result.Warnings = append(result.Warnings, warnings...)
		return result, nil
	case ".xls", ".ods":
		return extractedDocument{}, fmt.Errorf("unsupported spreadsheet format %s; export it as XLSX, CSV, or TSV", extension)
	default:
		data, err := readFileLimited(pathName, limits.MaxExtractedBytes)
		if err != nil {
			return extractedDocument{}, err
		}
		if !utf8.Valid(data) || bytes.ContainsRune(data, '\x00') {
			return extractedDocument{}, fmt.Errorf("unsupported binary document format %q", extension)
		}
		result.Text = string(data)
		result.Format = "text"
		result.Extractor = "direct"
		result.Warnings = append(result.Warnings, "unknown extension was treated as UTF-8 text")
		return result, nil
	}
}

func normalizeLimits(limits Limits) Limits {
	if limits.MaxInputBytes <= 0 {
		limits.MaxInputBytes = DefaultMaxInputBytes
	}
	if limits.MaxExtractedBytes <= 0 {
		limits.MaxExtractedBytes = DefaultMaxExtractedBytes
	}
	return limits
}

func hashFile(pathName string, limit int64) (string, error) {
	file, err := os.Open(pathName)
	if err != nil {
		return "", fmt.Errorf("open input for hashing: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, limit+1))
	if err != nil {
		return "", fmt.Errorf("hash input: %w", err)
	}
	if written > limit {
		return "", fmt.Errorf("input grew beyond %d bytes while reading", limit)
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func readFileLimited(pathName string, limit int64) ([]byte, error) {
	file, err := os.Open(pathName)
	if err != nil {
		return nil, fmt.Errorf("open input: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("extracted text exceeds %d bytes", limit)
	}
	return data, nil
}

func extractWithTextutil(ctx context.Context, pathName string, limit int64) ([]byte, error) {
	return runCommandLimited(ctx, limit, "/usr/bin/textutil", "-convert", "txt", "-encoding", "UTF-8", "-stdout", pathName)
}

func extractPDF(ctx context.Context, pathName string, limit int64) ([]byte, error) {
	binary, err := exec.LookPath("pdftotext")
	if err != nil {
		return nil, fmt.Errorf("pdftotext is required for PDF extraction; install it with: brew install poppler")
	}
	return runCommandLimited(ctx, limit, binary, "-layout", pathName, "-")
}

func runCommandLimited(ctx context.Context, limit int64, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("prepare extractor: %w", err)
	}
	stderr := &limitedBuffer{limit: 8192}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start extractor: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(stdout, limit+1))
	if int64(len(data)) > limit {
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, fmt.Errorf("extracted text exceeds %d bytes", limit)
	}
	waitErr := command.Wait()
	if readErr != nil {
		return nil, fmt.Errorf("read extractor output: %w", readErr)
	}
	if waitErr != nil {
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			message = filepath.Base(name) + " reported an error"
		}
		if message == "" {
			message = filepath.Base(name) + " failed"
		}
		return nil, fmt.Errorf("%s: %w", message, waitErr)
	}
	return data, nil
}

func normalizeDelimitedText(text string, delimiter rune, limit int64) (string, string) {
	reader := csv.NewReader(strings.NewReader(text))
	reader.Comma = delimiter
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	var output strings.Builder
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return text, "delimited-text parsing failed; raw UTF-8 text was sanitized instead"
		}
		for index, value := range row {
			if index > 0 {
				output.WriteByte('\t')
			}
			value = strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(value)
			output.WriteString(value)
		}
		output.WriteByte('\n')
		if int64(output.Len()) > limit {
			return text, "normalized table exceeded the extraction limit; raw UTF-8 text was sanitized instead"
		}
	}
	return output.String(), ""
}

type limitedBuffer struct {
	data  bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	remaining := b.limit - b.data.Len()
	if remaining > 0 {
		if len(data) > remaining {
			_, _ = b.data.Write(data[:remaining])
		} else {
			_, _ = b.data.Write(data)
		}
	}
	return len(data), nil
}

func (b *limitedBuffer) String() string {
	return b.data.String()
}
