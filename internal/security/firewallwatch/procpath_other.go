//go:build !darwin || !cgo

package firewallwatch

import "errors"

// resolveProcessImage cannot confirm a process here; nettop rows keep no path.
func resolveProcessImage(int, string) processImage { return processImage{} }

// staticCodeFacts cannot read a signature here.
func staticCodeFacts(string) (codeFacts, error) {
	return codeFacts{Signer: "unknown", CDHash: noCDHash}, errors.New("signatures are read on darwin only")
}
