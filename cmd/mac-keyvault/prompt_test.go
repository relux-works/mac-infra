package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/keyvault"
)

// promptHelper stands in for mac-keyvault-enclave with the owner confirming
// every prompt; it records the prompt reason of each sign request.
type promptHelper struct {
	keys    map[string]*ecdsa.PrivateKey
	reasons []string
}

func (h *promptHelper) Call(req keyvault.EnclaveRequest, interactive bool) (keyvault.EnclaveResponse, error) {
	switch req.Op {
	case "create":
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		blob := []byte("blob-" + string(rune('a'+len(h.keys))))
		h.keys[string(blob)] = key
		enforced := req.Presence == "user-presence"
		return keyvault.EnclaveResponse{Blob: blob, Point: elliptic.Marshal(elliptic.P256(), key.X, key.Y), PresenceEnforced: &enforced}, nil
	case "sign":
		h.reasons = append(h.reasons, req.Reason)
		key := h.keys[string(req.Blob)]
		der, err := ecdsa.SignASN1(rand.Reader, key, req.Digest)
		return keyvault.EnclaveResponse{DER: der, Point: elliptic.Marshal(elliptic.P256(), key.X, key.Y)}, err
	}
	return keyvault.EnclaveResponse{}, &keyvault.EnclaveHelperError{Code: "bad_request", Status: -50, Message: "unknown op"}
}

const promptStatement = "works.relux.vpn-core.authorize/v1\naction=install\ntarget=vpn-core\n" +
	"digest=07d46cd27e830a1f9f7b62c43a9b9cb5b0e94b43a135e89e934a15117ab56f88\n" +
	"nonce=0000000000000000000000000000000000000000000000000000000000000001\nexpires=2026-10-19T14:02:03Z\n"

// The parser recognises exactly the v1 vpn-core authorization statement
// (install or rollback) and names its action and package digest prefix;
// every near miss gets no description, so the prompt falls back to the
// generic sha256 text instead of naming a package that was not parsed.
func TestDescribeVPNCoreAuthorization(t *testing.T) {
	rollback := strings.Replace(promptStatement, "action=install", "action=rollback", 1)
	if got := describeVPNCoreAuthorization([]byte(promptStatement)); got != "authorize vpn-core install 07d46cd2" {
		t.Fatalf("install statement: %q", got)
	}
	if got := describeVPNCoreAuthorization([]byte(rollback)); got != "authorize vpn-core rollback 07d46cd2" {
		t.Fatalf("rollback statement: %q", got)
	}
	// describeData names the statement only for the digest of those bytes.
	sum := sha256.Sum256([]byte(promptStatement))
	describe := describeData([]byte(promptStatement))
	if describe(sum[:]) != "authorize vpn-core install 07d46cd2" || describe(make([]byte, 32)) != "" {
		t.Fatalf("describeData: own digest %q, other digest %q", describe(sum[:]), describe(make([]byte, 32)))
	}
	for name, data := range map[string]string{
		"other header":     strings.Replace(promptStatement, "authorize/v1", "authorize/v2", 1),
		"other action":     strings.Replace(promptStatement, "action=install", "action=remove", 1),
		"other target":     strings.Replace(promptStatement, "target=vpn-core", "target=sing-box", 1),
		"uppercase digest": strings.Replace(promptStatement, "07d46cd2", "07D46CD2", 1),
		"short digest":     strings.Replace(promptStatement, "56f88\n", "56f8\n", 1),
		"extra line":       promptStatement + "note=x\n",
		"trailing blank":   promptStatement + "\n",
		"no final newline": strings.TrimSuffix(promptStatement, "\n"),
		"no nonce line":    strings.Replace(promptStatement, "nonce=", "noise=", 1),
		"empty":            "",
	} {
		if got := describeVPNCoreAuthorization([]byte(data)); got != "" {
			t.Errorf("%s: described as %q", name, got)
		}
	}
}

// sign --data-file on a Touch ID/password enclave key shows the owner what
// is signed: an authorization statement's action and package digest prefix,
// any other file's sha256 prefix, and --digest (no data) the sha256 prefix.
// The description is cleared after each sign.
func TestSignPromptNamesTheSignedData(t *testing.T) {
	helper := &promptHelper{keys: map[string]*ecdsa.PrivateKey{}}
	enclave := describedEnclave(keyvault.NewEnclaveStore(filepath.Join(t.TempDir(), "enclave"), helper))
	useStore(t, keyvault.RoutedBackend{Keychain: newMemStore(), Enclave: enclave})
	if code, resp, _ := runJSON(t, initArgs("owner", "--enclave", "--user-presence")...); code != 0 {
		t.Fatalf("init: %d %+v", code, resp)
	}
	dir := t.TempDir()
	statement, other := filepath.Join(dir, "authz"), filepath.Join(dir, "other")
	mustWrite(t, statement, promptStatement)
	mustWrite(t, other, "not a statement\n")
	otherSum := sha256.Sum256([]byte("not a statement\n"))
	statementSum := sha256.Sum256([]byte(promptStatement))
	key := "test/owner v1"
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--data-file", statement}, "mac-keyvault: authorize vpn-core install 07d46cd2 with " + key},
		{[]string{"--data-file", other}, "mac-keyvault: sign sha256 " + hex.EncodeToString(otherSum[:4]) + " with " + key},
		{[]string{"--digest", hex.EncodeToString(statementSum[:])}, "mac-keyvault: sign sha256 " + hex.EncodeToString(statementSum[:4]) + " with " + key},
	} {
		if code, resp, _ := runJSON(t, append([]string{"sign", "test/owner"}, tc.args...)...); code != 0 {
			t.Fatalf("sign %v: %d %+v", tc.args, code, resp)
		}
		if got := helper.reasons[len(helper.reasons)-1]; got != tc.want {
			t.Fatalf("sign %v prompt %q, want %q", tc.args, got, tc.want)
		}
		if signDescription != nil {
			t.Fatalf("sign %v left signDescription set", tc.args)
		}
	}
}

func mustWrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}
