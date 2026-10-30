//go:build !darwin || !cgo

package firewallwatch

// resolveProcessImage cannot confirm a process here; nettop rows keep no path.
func resolveProcessImage(int, string) processImage { return processImage{} }
