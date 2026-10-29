//go:build !darwin || !cgo

package toolsecretprobe

import "fmt"

func nativeAttempt(Request) (int, error) { return 0, fmt.Errorf("probe requires macOS and cgo") }
