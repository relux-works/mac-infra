//go:build !darwin || !cgo

package toolsecret

import "fmt"

func terminalFD(int) bool { return false }
func nativeCall(string) (string, error) {
	return "", fmt.Errorf("mac-tool-secret requires macOS and cgo")
}
