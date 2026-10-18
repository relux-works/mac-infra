//go:build !darwin || !cgo

package maccore

import (
	"fmt"
	"os"
)

func secureVPNCoreFile(path string, dir bool, mode os.FileMode) error {
	return fmt.Errorf("vpn-core installation requires macOS with cgo ACL support")
}

func secureVPNCoreFileOwned(path string, dir bool, mode os.FileMode, uid, gid int) error {
	return secureVPNCoreFile(path, dir, mode)
}
