//go:build !darwin

package maccore

import "fmt"

func swapVPNCoreTrees(a, b string) error { return fmt.Errorf("vpn-core atomic swap requires macOS") }
