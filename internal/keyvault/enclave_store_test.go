package keyvault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeEnclave stands in for mac-keyvault-enclave: each blob names a Go key,
// and a key created with presence refuses every signature as the Secure
// Enclave does without a finger (errSecInteractionNotAllowed), unless
// fingerOK is set.
type fakeEnclave struct {
	keys     map[string]*ecdsa.PrivateKey
	presence map[string]bool
	requests []EnclaveRequest
	// interactive records the interactive flag of each call.
	interactive []bool
	// enforced overrides the presence verdict create reports.
	enforced *bool
	fingerOK bool
	failWith *EnclaveHelperError
	// pointFor overrides the public half sign reports.
	pointFor []byte
}

func newFakeEnclave() *fakeEnclave {
	return &fakeEnclave{keys: map[string]*ecdsa.PrivateKey{}, presence: map[string]bool{}}
}

func point(key *ecdsa.PrivateKey) []byte {
	return elliptic.Marshal(elliptic.P256(), key.X, key.Y)
}

func (f *fakeEnclave) Call(req EnclaveRequest, interactive bool) (EnclaveResponse, error) {
	f.requests = append(f.requests, req)
	f.interactive = append(f.interactive, interactive)
	if f.failWith != nil {
		return EnclaveResponse{}, f.failWith
	}
	switch req.Op {
	case "create":
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		blob := fmt.Sprintf("blob-%d", len(f.keys))
		f.keys[blob] = key
		f.presence[blob] = req.Presence == enclavePresenceBiometry
		enforced := f.presence[blob]
		if f.enforced != nil {
			enforced = *f.enforced
		}
		return EnclaveResponse{Blob: []byte(blob), Point: point(key), PresenceEnforced: &enforced}, nil
	case "sign":
		key, ok := f.keys[string(req.Blob)]
		if !ok {
			return EnclaveResponse{}, &EnclaveHelperError{Code: "invalid_blob", Status: -26275, Message: "the Secure Enclave refused the key blob"}
		}
		if req.Presence == enclavePresenceRequired && !f.presence[string(req.Blob)] {
			return EnclaveResponse{}, &EnclaveHelperError{Code: "presence_not_enforced", Status: -25293, Message: "the key signs without user presence although its record requires it; nothing was signed"}
		}
		if f.presence[string(req.Blob)] && (req.Interaction == "none" || !f.fingerOK) {
			return EnclaveResponse{}, &EnclaveHelperError{Code: "presence_required", Status: -25308, Message: "sign: user presence is required and interaction is not allowed"}
		}
		der, err := ecdsa.SignASN1(rand.Reader, key, req.Digest)
		if err != nil {
			return EnclaveResponse{}, err
		}
		p := point(key)
		if f.pointFor != nil {
			p = f.pointFor
		}
		return EnclaveResponse{DER: der, Point: p}, nil
	}
	return EnclaveResponse{}, &EnclaveHelperError{Code: "bad_request", Status: -50, Message: "unknown op"}
}

// enclaveFixture is a RoutedBackend over a recording keychain fake and an
// enclave store in a private temp dir.
func enclaveFixture(t *testing.T) (*Manager, *fakeStore, *EnclaveStore, *fakeEnclave) {
	t.Helper()
	helper := newFakeEnclave()
	enclave := NewEnclaveStore(filepath.Join(t.TempDir(), "enclave"), helper)
	keychain := newFakeStore()
	return newTestManager(t, RoutedBackend{Keychain: keychain, Enclave: enclave}), keychain, enclave, helper
}

func enclaveSpec(purpose string, presence bool) InitSpec {
	spec := validSpec(purpose)
	spec.Store = StoreEnclave
	spec.UserPresence = presence
	return spec
}

func refusalOf(t *testing.T, err error) *Refusal {
	t.Helper()
	var refusal *Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("err = %v, want a Refusal", err)
	}
	return refusal
}

// init --enclave --user-presence goes to the enclave store only, asks the
// helper for a biometry key, stores one private file and lists it with its
// public half; the keychain is never touched (no fallback).
func TestEnclaveInitStoresPresenceKeyWithoutKeychain(t *testing.T) {
	m, keychain, enclave, helper := enclaveFixture(t)
	key, err := m.Init(enclaveSpec("owner", true))
	if err != nil {
		t.Fatal(err)
	}
	if key.Record.Store != StoreEnclave || !key.Record.UserPresence || len(key.SPKI) == 0 {
		t.Fatalf("key = %+v", key)
	}
	if len(keychain.creates) != 0 {
		t.Fatalf("keychain create was called: %+v", keychain.creates)
	}
	if len(helper.requests) != 1 || helper.requests[0].Op != "create" || helper.requests[0].Presence != enclavePresenceBiometry {
		t.Fatalf("helper requests = %+v", helper.requests)
	}
	info, err := os.Lstat(filepath.Join(enclave.Dir, key.Label+".json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", info, err)
	}
	if dir, _ := os.Lstat(enclave.Dir); dir.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", dir.Mode().Perm())
	}
	listed, err := m.Describe(Address{Kind: KindKey, Service: TestService, Purpose: "owner"})
	if err != nil || listed.Fingerprint() != key.Fingerprint() || listed.RecordProblem != "" {
		t.Fatalf("describe: %+v %v", listed, err)
	}
	// Positive control of the other store: a keychain init still goes to
	// the keychain and never to the helper.
	if _, err := m.Init(validSpec("plain")); err != nil || len(keychain.creates) != 1 || len(helper.requests) != 1 {
		t.Fatalf("keychain init: %v creates=%d helper=%d", err, len(keychain.creates), len(helper.requests))
	}
}

// A key whose measured presence differs from the request is refused in both
// directions and nothing is stored; a helper failure creates nothing and
// never falls back to the keychain.
func TestEnclaveInitRefusesWrongPresenceAndNeverFallsBack(t *testing.T) {
	for _, tc := range []struct {
		name      string
		requested bool
		measured  bool
	}{
		{"asked presence, key has none", true, false},
		{"asked none, key enforces presence", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, keychain, enclave, helper := enclaveFixture(t)
			helper.enforced = &tc.measured
			_, err := m.Init(enclaveSpec("owner", tc.requested))
			if refusal := refusalOf(t, err); refusal.Code != CodeSecurity || !refusal.Failure {
				t.Fatalf("refusal = %+v", refusal)
			}
			if entries, _ := os.ReadDir(enclave.Dir); len(entries) != 0 || len(keychain.creates) != 0 {
				t.Fatalf("something was stored: files=%d keychain=%d", len(entries), len(keychain.creates))
			}
		})
	}
	t.Run("helper reports no Secure Enclave", func(t *testing.T) {
		m, keychain, enclave, helper := enclaveFixture(t)
		helper.failWith = &EnclaveHelperError{Code: "enclave_unavailable", Status: -25291, Message: "the Secure Enclave is not available"}
		_, err := m.Init(enclaveSpec("owner", true))
		if refusal := refusalOf(t, err); refusal.Code != CodeSecurity || refusal.Status != -25291 {
			t.Fatalf("refusal = %+v", refusal)
		}
		if entries, _ := os.ReadDir(enclave.Dir); len(entries) != 0 || len(keychain.creates) != 0 {
			t.Fatalf("something was stored: files=%d keychain=%d", len(entries), len(keychain.creates))
		}
	})
}

// Signing a presence key asks the helper interactively with presence
// required and a reason naming the address; the signature verifies under
// the stored key. A key without presence signs silently.
func TestEnclaveSignRoutesPresencePolicy(t *testing.T) {
	m, keychain, _, helper := enclaveFixture(t)
	helper.fingerOK = true
	digest := sha256.Sum256([]byte("owner signs"))
	for _, tc := range []struct {
		purpose     string
		presence    bool
		wantMode    string
		interactive bool
	}{
		{"owner", true, enclavePresenceRequired, true},
		{"silent", false, enclavePresenceNone, false},
	} {
		if _, err := m.Init(enclaveSpec(tc.purpose, tc.presence)); err != nil {
			t.Fatal(err)
		}
		result, err := m.Sign(Address{Kind: KindKey, Service: TestService, Purpose: tc.purpose}, digest[:])
		if err != nil {
			t.Fatalf("%s: %v", tc.purpose, err)
		}
		if ok, err := VerifyDigest(result.Key.SPKI, digest[:], result.Signature); err != nil || !ok {
			t.Fatalf("%s: signature does not verify", tc.purpose)
		}
		last := helper.requests[len(helper.requests)-1]
		if last.Op != "sign" || last.Presence != tc.wantMode || helper.interactive[len(helper.interactive)-1] != tc.interactive || last.Interaction != "" {
			t.Fatalf("%s: request %+v interactive=%v", tc.purpose, last, helper.interactive)
		}
		if want := "mac-keyvault: sign with test/" + tc.purpose + " v1"; last.Reason != want {
			t.Fatalf("reason %q, want %q", last.Reason, want)
		}
	}
	if len(keychain.signs) != 0 {
		t.Fatalf("keychain signed: %v", keychain.signs)
	}
}

// Without the owner's finger a presence key yields no signature: the
// refusal is security with errSecInteractionNotAllowed (or the canceled
// prompt's errSecUserCanceled), and NonInteractive forbids the prompt.
func TestEnclaveSignWithoutPresenceIsRefused(t *testing.T) {
	addr := Address{Kind: KindKey, Service: TestService, Purpose: "owner"}
	digest := sha256.Sum256([]byte("no finger"))
	t.Run("no finger", func(t *testing.T) {
		m, _, _, _ := enclaveFixture(t)
		if _, err := m.Init(enclaveSpec("owner", true)); err != nil {
			t.Fatal(err)
		}
		_, err := m.Sign(addr, digest[:])
		if refusal := refusalOf(t, err); refusal.Code != CodeSecurity || refusal.Status != -25308 || !strings.Contains(refusal.Message, "errSecInteractionNotAllowed") {
			t.Fatalf("refusal = %+v", refusal)
		}
	})
	t.Run("non-interactive store", func(t *testing.T) {
		m, _, enclave, helper := enclaveFixture(t)
		helper.fingerOK = true
		enclave.NonInteractive = true
		if _, err := m.Init(enclaveSpec("owner", true)); err != nil {
			t.Fatal(err)
		}
		_, err := m.Sign(addr, digest[:])
		last := helper.requests[len(helper.requests)-1]
		if refusal := refusalOf(t, err); refusal.Status != -25308 || last.Interaction != "none" || helper.interactive[len(helper.interactive)-1] {
			t.Fatalf("refusal = %+v request = %+v", refusal, last)
		}
	})
	t.Run("canceled prompt", func(t *testing.T) {
		m, _, _, helper := enclaveFixture(t)
		if _, err := m.Init(enclaveSpec("owner", true)); err != nil {
			t.Fatal(err)
		}
		helper.failWith = &EnclaveHelperError{Code: "user_canceled", Status: -128, Message: "sign: the presence prompt was canceled"}
		_, err := m.Sign(addr, digest[:])
		if refusal := refusalOf(t, err); refusal.Status != -128 || !strings.Contains(refusal.Message, "errSecUserCanceled") {
			t.Fatalf("refusal = %+v", refusal)
		}
	})
}

// A file whose blob, public half or presence no longer match is never used:
// a swapped blob, a blob that signs silently under a presence record, and a
// helper-reported public half that differs from the stored one all refuse
// without emitting a signature.
func TestEnclaveSignRefusesSwappedOrTamperedKeys(t *testing.T) {
	addr := Address{Kind: KindKey, Service: TestService, Purpose: "owner"}
	digest := sha256.Sum256([]byte("tamper"))
	setup := func(t *testing.T) (*Manager, *EnclaveStore, *fakeEnclave, string) {
		m, _, enclave, helper := enclaveFixture(t)
		helper.fingerOK = true
		key, err := m.Init(enclaveSpec("owner", true))
		if err != nil {
			t.Fatal(err)
		}
		return m, enclave, helper, key.Label
	}
	rewrite := func(t *testing.T, enclave *EnclaveStore, label string, change func(*enclaveFile)) {
		file, err := enclave.read(label)
		if err != nil {
			t.Fatal(err)
		}
		change(&file)
		path, _ := enclave.path(label)
		if err := enclave.write(path, file, true); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("blob of another presence key", func(t *testing.T) {
		m, enclave, helper, label := setup(t)
		other, _ := helper.Call(EnclaveRequest{Op: "create", Presence: enclavePresenceBiometry}, false)
		rewrite(t, enclave, label, func(f *enclaveFile) { f.Blob = other.Blob })
		_, err := m.Sign(addr, digest[:])
		if refusal := refusalOf(t, err); refusal.Code != CodeSecurity || !strings.Contains(refusal.Message, "does not belong to the stored public key") {
			t.Fatalf("refusal = %+v", refusal)
		}
	})
	t.Run("blob of a key without presence", func(t *testing.T) {
		m, enclave, helper, label := setup(t)
		other, _ := helper.Call(EnclaveRequest{Op: "create", Presence: enclavePresenceNone}, false)
		rewrite(t, enclave, label, func(f *enclaveFile) { f.Blob, f.Point = other.Blob, other.Point })
		_, err := m.Sign(addr, digest[:])
		if refusal := refusalOf(t, err); refusal.Code != CodeSecurity || !strings.Contains(refusal.Message, "without user presence") {
			t.Fatalf("refusal = %+v", refusal)
		}
	})
	t.Run("unknown blob", func(t *testing.T) {
		m, enclave, _, label := setup(t)
		rewrite(t, enclave, label, func(f *enclaveFile) { f.Blob = []byte("not a blob") })
		_, err := m.Sign(addr, digest[:])
		if refusal := refusalOf(t, err); refusal.Code != CodeSecurity || !strings.Contains(refusal.Message, "refused the key blob") {
			t.Fatalf("refusal = %+v", refusal)
		}
	})
	t.Run("helper reports another public half", func(t *testing.T) {
		m, _, helper, _ := setup(t)
		stranger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		helper.pointFor = point(stranger)
		if _, err := m.Sign(addr, digest[:]); refusalOf(t, err).Code != CodeSecurity {
			t.Fatalf("err = %v", err)
		}
	})
	// Positive control: the untouched key signs.
	t.Run("untouched control", func(t *testing.T) {
		m, _, _, _ := setup(t)
		if _, err := m.Sign(addr, digest[:]); err != nil {
			t.Fatal(err)
		}
	})
}

// Unsafe key files are listed with a problem and never used: a symlink, a
// group-readable file, a file whose label differs from its name and a
// non-JSON file. An open directory refuses the whole store.
func TestEnclaveStoreRefusesUnsafeFiles(t *testing.T) {
	addr := Address{Kind: KindKey, Service: TestService, Purpose: "owner"}
	digest := sha256.Sum256([]byte("unsafe"))
	for name, damage := range map[string]func(t *testing.T, path string){
		"symlink": func(t *testing.T, path string) {
			moved := path + ".real"
			if err := os.Rename(path, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, path); err != nil {
				t.Fatal(err)
			}
		},
		"group readable": func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o640); err != nil {
				t.Fatal(err)
			}
		},
		"label mismatch": func(t *testing.T, path string) {
			data, _ := os.ReadFile(path)
			if err := os.WriteFile(path, []byte(strings.Replace(string(data), ".owner.v1", ".other.v1", 1)), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"not json": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			m, _, enclave, helper := enclaveFixture(t)
			helper.fingerOK = true
			key, err := m.Init(enclaveSpec("owner", true))
			if err != nil {
				t.Fatal(err)
			}
			damage(t, filepath.Join(enclave.Dir, key.Label+".json"))
			described, err := m.Describe(addr)
			if err != nil || !strings.HasPrefix(described.RecordProblem, "enclave file refused") {
				t.Fatalf("describe: %+v %v", described, err)
			}
			signs := len(helper.requests)
			if _, err := m.Sign(addr, digest[:]); refusalOf(t, err).Code != CodeMetadataUnknown || len(helper.requests) != signs {
				t.Fatalf("sign: %v helper calls %d -> %d", err, signs, len(helper.requests))
			}
			if _, err := enclave.Sign(key.Label, digest[:]); err == nil || len(helper.requests) != signs {
				t.Fatalf("store sign reached the helper: %v", err)
			}
		})
	}
	t.Run("open directory", func(t *testing.T) {
		m, _, enclave, _ := enclaveFixture(t)
		if _, err := m.Init(enclaveSpec("owner", false)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(enclave.Dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := m.List("", ""); err == nil {
			t.Fatal("an open enclave directory was listed")
		}
	})
}

// A label present in both stores is listed with a problem on both sides and
// never signed; meta updates rewrite only the record of an enclave key.
func TestRoutedBackendDuplicateLabelAndMeta(t *testing.T) {
	m, keychain, enclave, helper := enclaveFixture(t)
	helper.fingerOK = true
	key, err := m.Init(enclaveSpec("owner", true))
	if err != nil {
		t.Fatal(err)
	}
	before, _ := enclave.read(key.Label)
	if _, err := m.MetaSet(Address{Kind: KindKey, Service: TestService, Purpose: "owner"}, "role", "ca"); err != nil {
		t.Fatal(err)
	}
	after, _ := enclave.read(key.Label)
	if string(after.Blob) != string(before.Blob) || string(after.Point) != string(before.Point) || !strings.Contains(after.Tag, `"role":"ca"`) || len(keychain.updates) != 0 {
		t.Fatalf("meta rewrite: before %+v after %+v keychain updates %v", before, after, keychain.updates)
	}
	keychain.keys[key.Label] = testItem(key.Label)
	digest := sha256.Sum256([]byte("dup"))
	if _, err := m.Sign(Address{Kind: KindKey, Service: TestService, Purpose: "owner"}, digest[:]); refusalOf(t, err).Code != CodeMetadataUnknown {
		t.Fatalf("duplicate label signed: %v", err)
	}
	keys, _ := m.List("", "")
	problems := 0
	for _, k := range keys {
		if k.Label == key.Label && strings.Contains(k.RecordProblem, "both the keychain and the enclave store") {
			problems++
		}
	}
	if problems != 2 {
		t.Fatalf("problems = %d, keys %+v", problems, keys)
	}
}

// Without a resolvable helper enclave keys are still listed and deletable,
// but sign refuses as unsupported_primitive before any helper call, and
// keychain keys keep working.
func TestEnclaveStoreWithoutHelper(t *testing.T) {
	m, keychain, enclave, helper := enclaveFixture(t)
	if _, err := m.Init(enclaveSpec("owner", false)); err != nil {
		t.Fatal(err)
	}
	enclave.helperErr = errors.New("mac-keyvault-enclave is missing")
	calls := len(helper.requests)
	digest := sha256.Sum256([]byte("no helper"))
	if _, err := m.Sign(Address{Kind: KindKey, Service: TestService, Purpose: "owner"}, digest[:]); refusalOf(t, err).Code != CodeUnsupportedPrimitive || len(helper.requests) != calls {
		t.Fatalf("sign without helper: %v", err)
	}
	if _, err := m.Init(enclaveSpec("second", false)); err == nil {
		t.Fatal("created an enclave key without a helper")
	}
	plain := tl("plain", 1)
	keychain.keys[plain] = testItem(plain)
	if keys, err := m.List("", ""); err != nil || len(keys) != 2 {
		t.Fatalf("list: %v %d", err, len(keys))
	}
	if label, err := m.Delete(Address{Kind: KindKey, Service: TestService, Purpose: "owner"}, true); err != nil || !strings.HasSuffix(label, ".owner.v1") {
		t.Fatalf("delete: %v", err)
	}
	if entries, _ := os.ReadDir(enclave.Dir); len(entries) != 0 {
		t.Fatalf("file left after delete: %d", len(entries))
	}
}
