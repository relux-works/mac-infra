package main

import (
	"bytes"
	"crypto/sha256"
	"strings"

	"github.com/relux-works/mac-infra/internal/keyvault"
)

// signDescription, set by sign for the data it hashed, words the presence
// prompt of an enclave key; nil keeps the store's generic sha256 text.
var signDescription func(digest []byte) string

// describedEnclave words store's presence prompts from signDescription.
func describedEnclave(store *keyvault.EnclaveStore) *keyvault.EnclaveStore {
	store.Describe = func(digest []byte) string {
		if signDescription == nil {
			return ""
		}
		return signDescription(digest)
	}
	return store
}

// describeData returns a prompt description for data whose sha256 is the
// digest being signed: the action and package digest prefix of a vpn-core
// authorization statement, so the owner matches what the agent announced.
// Anything else, or a statement that does not parse exactly, returns "".
func describeData(data []byte) func(digest []byte) string {
	sum := sha256.Sum256(data)
	what := describeVPNCoreAuthorization(data)
	return func(digest []byte) string {
		if !bytes.Equal(digest, sum[:]) {
			return ""
		}
		return what
	}
}

// describeVPNCoreAuthorization recognises the first lines of the
// works.relux.vpn-core.authorize/v1 statement that mac-infra-core issues.
// The root helper, not this parser, decides whether a statement is valid.
func describeVPNCoreAuthorization(data []byte) string {
	lines := strings.Split(string(data), "\n")
	if len(lines) != 7 || lines[0] != "works.relux.vpn-core.authorize/v1" || lines[6] != "" {
		return ""
	}
	action := strings.TrimPrefix(lines[1], "action=")
	digest := strings.TrimPrefix(lines[3], "digest=")
	if (action != "install" && action != "rollback") || lines[2] != "target=vpn-core" || !isLowerHex(digest, 64) ||
		!strings.HasPrefix(lines[4], "nonce=") || !strings.HasPrefix(lines[5], "expires=") {
		return ""
	}
	return "authorize vpn-core " + action + " " + digest[:8]
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
