package docsanitize

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func DefaultArtifactPaths(rootDir, sourceSHA256 string) (string, string, error) {
	if len(sourceSHA256) < 12 {
		return "", "", fmt.Errorf("source hash is unavailable")
	}
	if strings.TrimSpace(rootDir) == "" {
		rootDir = filepath.Join(".temp", "mac-document-sanitize")
	}
	stem := "document-" + sourceSHA256[:12]
	return filepath.Join(rootDir, stem+".sanitized.txt"), filepath.Join(rootDir, stem+".redaction.json"), nil
}

func WriteTextArtifact(pathName, text string) error {
	return writePrivateFile(pathName, []byte(text))
}

func WriteReportArtifact(pathName string, report Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	data = append(data, '\n')
	return writePrivateFile(pathName, data)
}

func writePrivateFile(pathName string, data []byte) error {
	if strings.TrimSpace(pathName) == "" {
		return fmt.Errorf("artifact path is required")
	}
	dir := filepath.Dir(pathName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create artifact directory: %w", err)
	}
	temporary, err := os.CreateTemp(dir, ".mac-document-sanitize-*")
	if err != nil {
		return fmt.Errorf("create temporary artifact: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("chmod temporary artifact: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary artifact: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary artifact: %w", err)
	}
	if err := os.Rename(temporaryPath, pathName); err != nil {
		return fmt.Errorf("publish artifact: %w", err)
	}
	if err := os.Chmod(pathName, 0o600); err != nil {
		return fmt.Errorf("chmod artifact: %w", err)
	}
	return nil
}
