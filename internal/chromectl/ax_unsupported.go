//go:build !darwin || !cgo

package chromectl

import "fmt"

func chromeAXProcessID() (int, error) {
	return 0, fmt.Errorf("Chrome Accessibility refused: platform-unsupported")
}

func chromeAXTypeText(int, string, string) error {
	return fmt.Errorf("Chrome Accessibility refused: platform-unsupported")
}

func chromeAXPress(int, string) error {
	return fmt.Errorf("Chrome Accessibility refused: platform-unsupported")
}

func chromeAXUploadFiles(int, string, string) error {
	return fmt.Errorf("Chrome Accessibility refused: platform-unsupported")
}
