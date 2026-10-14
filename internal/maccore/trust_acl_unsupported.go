//go:build !darwin || !cgo

package maccore

import "fmt"

func requireSafeACL(fd int) error {
	return fmt.Errorf("privileged installation trust checks require macOS with cgo ACL support")
}
