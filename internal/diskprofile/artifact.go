package diskprofile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func WriteJSONArtifact(pathName string, result ScanResult) error {
	if pathName == "" {
		return fmt.Errorf("artifact path is empty")
	}
	dir := filepath.Dir(pathName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create artifact dir: %w", err)
	}

	file, err := os.OpenFile(pathName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create artifact: %w", err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		_ = file.Close()
		return fmt.Errorf("write artifact: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close artifact: %w", err)
	}
	if err := os.Chmod(pathName, 0o600); err != nil {
		return fmt.Errorf("chmod artifact: %w", err)
	}
	return nil
}
