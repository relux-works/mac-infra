//go:build darwin && cgo

package keyvault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GuardedStore wraps a Backend and fails the test process before any Create,
// Delete or UpdateTag whose label is outside the test namespace (service
// "test", see IsTestLabel) reaches the real keychain. Every integration test
// in this repository goes through it.
type GuardedStore struct {
	Backend
	touched []string
}

// ErrGuardedLabel is returned when a test tries to touch a non-test label.
var ErrGuardedLabel = errors.New("test guard: label outside the test namespace " + TestLabelPrefix)

func (g *GuardedStore) guard(label string) error {
	if !IsTestLabel(label) {
		return fmt.Errorf("%w: %q", ErrGuardedLabel, label)
	}
	g.touched = append(g.touched, label)
	return nil
}

func (g *GuardedStore) Create(opts CreateOptions) (Item, error) {
	if err := g.guard(opts.Label); err != nil {
		return Item{}, err
	}
	return g.Backend.Create(opts)
}

func (g *GuardedStore) Delete(label string) error {
	if err := g.guard(label); err != nil {
		return err
	}
	return g.Backend.Delete(label)
}

func (g *GuardedStore) UpdateTag(label string, tag []byte) error {
	if err := g.guard(label); err != nil {
		return err
	}
	return g.Backend.UpdateTag(label, tag)
}

func newGuardedSecurityStore(t *testing.T) *GuardedStore {
	t.Helper()
	store := &GuardedStore{Backend: NewSecurityStore()}
	t.Cleanup(func() {
		for _, label := range store.touched {
			if err := store.Backend.Delete(label); err != nil && !errors.Is(err, ErrNotFound) {
				t.Errorf("cleanup %s: %v", label, err)
			}
		}
	})
	return store
}

// testLabel is works.relux.mac-keyvault.key.test.<suffix>-<pid>.v1: kind
// key, service "test", purpose "<suffix>-<pid>", version 1.
func testLabel(t *testing.T, suffix string) string {
	return tl(fmt.Sprintf("%s-%d", suffix, os.Getpid()), 1)
}

func testTag(t *testing.T, label string) []byte {
	t.Helper()
	tag, err := EncodeRecord(testRecord(label))
	if err != nil {
		t.Fatal(err)
	}
	return tag
}

// The guard itself refuses non-test labels (positive control for every
// integration test below): a foreign or production-prefixed label never
// reaches the wrapped backend.
func TestGuardedStoreRefusesNonTestLabels(t *testing.T) {
	inner := newFakeStore(LabelPrefix + "prod")
	store := &GuardedStore{Backend: inner}
	for _, label := range []string{LabelPrefix + "prod", LabelPrefix + "key.kvctl.pki.v1", LabelPrefix + "key.testx.a.v1", "com.apple.security.key", TestLabelPrefix, LabelPrefix + "test.", ""} {
		if _, err := store.Create(CreateOptions{Label: label, Store: StoreKeychain}); !errors.Is(err, ErrGuardedLabel) {
			t.Fatalf("create %q: err = %v", label, err)
		}
		if err := store.Delete(label); !errors.Is(err, ErrGuardedLabel) {
			t.Fatalf("delete %q: err = %v", label, err)
		}
		if err := store.UpdateTag(label, nil); !errors.Is(err, ErrGuardedLabel) {
			t.Fatalf("update %q: err = %v", label, err)
		}
	}
	if len(inner.creates) != 0 || len(inner.deletes) != 0 || len(inner.updates) != 0 {
		t.Fatalf("guard leaked calls: creates=%v deletes=%v updates=%v", inner.creates, inner.deletes, inner.updates)
	}
	if _, ok := inner.keys[LabelPrefix+"prod"]; !ok {
		t.Fatal("production key was deleted through the guard")
	}
	if len(inner.keys) != 1 {
		t.Fatalf("guard let a create through: %v", inner.keys)
	}
	for _, label := range []string{tl("ok", 1), LabelPrefix + "secret.test.tok.v2", LabelPrefix + "test.rev1-leftover"} {
		if _, err := store.Create(CreateOptions{Label: label, Store: StoreKeychain}); err != nil {
			t.Fatalf("test label %s refused: %v", label, err)
		}
	}
}

// Login-keychain round trip on this Mac: Create persists a P-256 pair whose
// SPKI is a 91-byte DER, List returns it with the exact record tag, UpdateTag
// replaces the tag in place, Delete removes both key halves so a second
// Delete is ErrNotFound.
func TestSecurityStoreKeychainRoundTrip(t *testing.T) {
	store := newGuardedSecurityStore(t)
	label := testLabel(t, "roundtrip")
	tag := testTag(t, label)

	item, err := store.Create(CreateOptions{Label: label, Tag: tag, Store: StoreKeychain})
	if err != nil {
		t.Fatal(err)
	}
	if len(item.SPKI) != 91 || (Key{SPKI: item.SPKI}).Fingerprint() == "" {
		t.Fatalf("spki = %x", item.SPKI)
	}

	find := func() *Item {
		items, err := store.List()
		if err != nil {
			t.Fatal(err)
		}
		for i := range items {
			if !strings.HasPrefix(items[i].Label, LabelPrefix) {
				t.Fatalf("bridge listed a foreign label %q", items[i].Label)
			}
			if items[i].Label == label {
				return &items[i]
			}
		}
		return nil
	}
	listed := find()
	if listed == nil {
		t.Fatal("created key missing from list")
	}
	if string(listed.Tag) != string(tag) || (Key{SPKI: listed.SPKI}).Fingerprint() != (Key{SPKI: item.SPKI}).Fingerprint() {
		t.Fatalf("listed = %+v, created = %+v", *listed, item)
	}
	rec, problem := DecodeRecord(listed.Tag)
	if problem != "" || rec.Schema != 2 || rec.Service != TestService || !strings.HasPrefix(rec.Purpose, "roundtrip-") {
		t.Fatalf("listed record = %+v (%s)", rec, problem)
	}

	rec.Meta["owner"] = "alexis"
	updated, _ := EncodeRecord(rec)
	if err := store.UpdateTag(label, updated); err != nil {
		t.Fatal(err)
	}
	if listed = find(); listed == nil || string(listed.Tag) != string(updated) {
		t.Fatalf("tag after update = %+v", listed)
	}
	if err := store.UpdateTag(testLabel(t, "never-created"), updated); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update of a missing label: %v", err)
	}

	if err := store.Delete(label); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(label); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete err = %v, want ErrNotFound (a key half survived)", err)
	}
	if find() != nil {
		t.Fatal("deleted key still listed")
	}
}

// errSecDataNotAvailable is what Security.framework answers when private
// material of a CSSM_KEYATTR_EXTRACTABLE-cleared key is requested.
const errSecDataNotAvailable = -25316

// Attestation (review F5): the private half the bridge creates cannot leave
// the keychain. SecKeyCopyExternalRepresentation and
// SecItemExport(kSecFormatWrappedPKCS8) both fail with errSecDataNotAvailable
// and hand back zero bytes, while the public half stays readable. Bound: the
// probe runs from the binary the ACL trusts, so a success here would mean the
// item itself is extractable, not that the ACL was bypassed.
func TestSecurityStorePrivateKeyIsNotExtractable(t *testing.T) {
	store := newGuardedSecurityStore(t)
	label := testLabel(t, "noexport")
	item, err := store.Create(CreateOptions{Label: label, Tag: testTag(t, label), Store: StoreKeychain})
	if err != nil {
		t.Fatal(err)
	}
	probe, err := store.Backend.(*SecurityStore).ProbeExport(label)
	if err != nil {
		t.Fatal(err)
	}
	if probe.RepresentationStatus != errSecDataNotAvailable || probe.ExportStatus != errSecDataNotAvailable || probe.LeakedBytes != 0 {
		t.Fatalf("private key export probe = %+v; want both paths refused with %d and zero bytes", probe, errSecDataNotAvailable)
	}
	if len(item.SPKI) != 91 {
		t.Fatalf("public half unreadable after non-extractable create: %x", item.SPKI)
	}
	if _, err := store.Backend.(*SecurityStore).ProbeExport(testLabel(t, "never-created")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("probe of a missing label: %v", err)
	}
}

// Attestation (review F5): the SecAccess installed on the private half
// trusts exactly the calling binary for every private-key authorization
// (sign, decrypt, derive, export) and no entry grants one of those to any
// application. The Encrypt/Integrity/PartitionID entries the keychain adds
// for public operations are allowed to be open; ChangeACL trusts nobody.
func TestSecurityStoreACLTrustsOnlyCallingBinary(t *testing.T) {
	store := newGuardedSecurityStore(t)
	label := testLabel(t, "acl")
	if _, err := store.Create(CreateOptions{Label: label, Tag: testTag(t, label), Store: StoreKeychain}); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	self, _ = filepath.EvalSymlinks(self)
	entries, err := store.Backend.(*SecurityStore).DescribeACL(label)
	if err != nil {
		t.Fatal(err)
	}
	private := map[string]bool{"ACLAuthorizationSign": true, "ACLAuthorizationDecrypt": true, "ACLAuthorizationDerive": true, "ACLAuthorizationExportClear": true, "ACLAuthorizationExportWrapped": true, "ACLAuthorizationMAC": true}
	covered := map[string]bool{}
	for _, entry := range entries {
		guardsPrivate := false
		for _, auth := range entry.Authorizations {
			if private[auth] {
				guardsPrivate = true
				covered[auth] = true
			}
		}
		if !guardsPrivate {
			continue
		}
		apps := make([]string, 0, len(entry.Applications))
		for _, app := range entry.Applications {
			resolved, _ := filepath.EvalSymlinks(app)
			apps = append(apps, resolved)
		}
		if entry.AnyApplication || len(apps) != 1 || apps[0] != self {
			t.Fatalf("private-key ACL entry %v trusts %v (any=%v); want exactly %s", entry.Authorizations, entry.Applications, entry.AnyApplication, self)
		}
	}
	for auth := range private {
		if !covered[auth] {
			t.Fatalf("no ACL entry covers %s: %+v", auth, entries)
		}
	}
	if _, err := store.Backend.(*SecurityStore).DescribeACL(testLabel(t, "never-created")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("acl of a missing label: %v", err)
	}
}

// Creating the same label twice at the bridge level is possible in the legacy
// keychain, which is why Manager must gate duplicates itself under the lock;
// this test pins that bound so the gate is not mistaken for a keychain
// guarantee.
func TestSecurityStoreDoesNotRefuseDuplicateLabelsItself(t *testing.T) {
	store := newGuardedSecurityStore(t)
	label := testLabel(t, "dupbridge")
	for i := 0; i < 2; i++ {
		if _, err := store.Create(CreateOptions{Label: label, Tag: testTag(t, label), Store: StoreKeychain}); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	rec := testRecord(label)
	if _, err := newTestManager(t, store).Init(validSpec(rec.Purpose)); refusalCode(t, err) != CodeDuplicate {
		t.Fatal("manager admitted the duplicate")
	}
	if err := store.Delete(label); err != nil {
		t.Fatal(err)
	}
}

// On this unprovisioned binary the Secure Enclave and user-presence shapes
// return exactly -34018 from Security.framework and leave no key behind.
// Bound: on a binary signed with a provisioning profile these creates would
// succeed and this test would report that as a failure to re-decide.
func TestSecurityStoreEnclaveAndUserPresenceReturnMissingEntitlement(t *testing.T) {
	store := newGuardedSecurityStore(t)
	for name, opts := range map[string]CreateOptions{
		"enclave":       {Store: StoreEnclave},
		"user-presence": {Store: StoreKeychain, UserPresence: true},
	} {
		t.Run(name, func(t *testing.T) {
			opts.Label = testLabel(t, name)
			opts.Tag = testTag(t, opts.Label)
			_, err := store.Create(opts)
			var status *StatusError
			if !errors.As(err, &status) || status.Status != errSecMissingEntitlement {
				t.Fatalf("err = %v, want OSStatus -34018", err)
			}
			if err := store.Backend.Delete(opts.Label); !errors.Is(err, ErrNotFound) {
				t.Fatalf("a key was persisted despite -34018: delete err = %v", err)
			}
		})
	}
}

// Deleting a test label that does not exist is ErrNotFound rather than a
// silent success.
func TestSecurityStoreDeleteMissingIsNotFound(t *testing.T) {
	store := newGuardedSecurityStore(t)
	if err := store.Delete(testLabel(t, "never-created")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

// Bridge records are framed by US/RS bytes with a hex point; a truncated
// record is an error, an unreadable point yields an item without SPKI, the
// tag bytes pass through verbatim, and a point containing framing bytes
// survives because it is hex encoded.
func TestParseListRecords(t *testing.T) {
	gx := "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
	gy := "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
	record := func(label, tag, status, point string) string {
		return label + "\x1f" + tag + "\x1f" + status + "\x1f" + point + "\x1e"
	}
	items, err := parseListRecords([]byte(record(LabelPrefix+"a", `{"schema":2}`, "0", "04"+gx+gy) + record(LabelPrefix+"b", "", "-2", "")))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || len(items[0].SPKI) != 91 || string(items[0].Tag) != `{"schema":2}` || len(items[1].SPKI) != 0 || len(items[1].Tag) != 0 {
		t.Fatalf("items = %+v", items)
	}
	if _, err := parseListRecords([]byte("only\x1ftwo\x1e")); err == nil {
		t.Fatal("truncated record accepted")
	}
	if _, err := parseListRecords([]byte(record(LabelPrefix+"c", "", "0", "zz"))); err == nil {
		t.Fatal("malformed hex accepted")
	}
	if _, err := parseListRecords([]byte(record(LabelPrefix+"d", "", "0", "04"+gx+gx))); err == nil {
		t.Fatal("off-curve point accepted")
	}
}

// ACL records decode "auths|apps" entries: "*" is any application, an
// empty application column is no application.
func TestParseACLRecords(t *testing.T) {
	entries := parseACLRecords([]byte("ACLAuthorizationEncrypt|*\x1eACLAuthorizationSign,ACLAuthorizationDecrypt|/a;/b\x1eACLAuthorizationChangeACL|\x1e"))
	if len(entries) != 3 || !entries[0].AnyApplication || len(entries[1].Applications) != 2 || entries[1].Authorizations[1] != "ACLAuthorizationDecrypt" || entries[2].AnyApplication || len(entries[2].Applications) != 0 {
		t.Fatalf("entries = %+v", entries)
	}
}
