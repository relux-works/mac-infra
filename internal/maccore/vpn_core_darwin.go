//go:build darwin

package maccore

import "golang.org/x/sys/unix"

func swapVPNCoreTrees(a, b string) error { return unix.RenamexNp(a, b, unix.RENAME_SWAP) }
