//go:build !darwin || !cgo

package firewallwatch

// resolveProcessPath cannot confirm a process here; nettop rows keep no path.
func resolveProcessPath(int, string) string { return "" }
