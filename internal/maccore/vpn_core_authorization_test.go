package maccore

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func signVPNStatement(t *testing.T, key *ecdsa.PrivateKey, statement []byte) []byte {
	t.Helper()
	hash := sha256.Sum256(statement)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	mustVPN(t, err)
	half := new(big.Int).Rsh(new(big.Int).Set(key.Params().N), 1)
	if s.Cmp(half) > 0 {
		s.Sub(key.Params().N, s)
	}
	signature, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	mustVPN(t, err)
	return signature
}

// Existing package tests issue/sign through the shared nonce seam without adding authorize audit entries to their old audit assertions.
func (f *vpnFixture) signRequest(t *testing.T, action Action, req *VPNCoreRequest) {
	t.Helper()
	statement, err := f.s.issueAuthorization(f.s.uid, strings.TrimPrefix(string(action), "vpn_core_"), req.ExpectedDigest)
	mustVPN(t, err)
	req.Authorization = statement
	req.Signature = signVPNStatement(t, f.key, statement)
}

func authorizeVPN(t *testing.T, f *vpnFixture, uid int, action, digest string) *VPNCoreRequest {
	t.Helper()
	response := f.s.handle(ActionVPNCoreAuthorize, &VPNCoreRequest{Target: "vpn-core", AuthorizeAction: action, ExpectedDigest: digest}, uid)
	if !response.OK {
		t.Fatal(response.Error)
	}
	return &VPNCoreRequest{Target: "vpn-core", ExpectedDigest: digest, Authorization: response.Authorization, Signature: signVPNStatement(t, f.key, response.Authorization)}
}

func pendingVPN(s *vpnCoreService, statement []byte) bool {
	parsed, err := parseAuthorization(statement)
	if err != nil {
		return false
	}
	s.authorizations.mu.Lock()
	defer s.authorizations.mu.Unlock()
	for _, p := range s.authorizations.pending {
		if p.nonce == parsed.nonce {
			return true
		}
	}
	return false
}

func refusalUnchangedVPN(t *testing.T, f *vpnFixture, action Action, req *VPNCoreRequest, uid int, code string) {
	t.Helper()
	before := f.snapshot(t)
	stageCalls := 0
	originalSecure := f.s.ops.secure
	f.s.ops.secure = func(path string, dir bool, mode os.FileMode) error {
		if path != f.s.audit {
			stageCalls++
		}
		return originalSecure(path, dir, mode)
	}
	defer func() { f.s.ops.secure = originalSecure }()
	sourceCalls := 0
	originalSource := f.s.ops.source
	f.s.ops.source = vpnCoreSourceFunc(func(ctx context.Context, path string, uid, gid int, consume func(io.Reader) error) error {
		sourceCalls++
		return originalSource.Read(ctx, path, uid, gid, consume)
	})
	defer func() { f.s.ops.source = originalSource }()
	f.calls = nil
	requireVPNCode(t, f.s.handle(action, req, uid), code)
	if f.snapshot(t) != before || len(f.calls) != 0 {
		t.Fatal("authorization refusal changed install/plist or called launchctl")
	}
	if strings.HasPrefix(code, "authorization_") || strings.HasPrefix(code, "owner_") {
		if stageCalls != 0 || sourceCalls != 0 {
			t.Fatal("authorization refusal staged files or read package")
		}
	}
	entries := auditVPN(t, f)
	if last := entries[len(entries)-1]; last["error_code"] != code || last["outcome"] != "refused" {
		t.Fatalf("missing refusal audit: %v", last)
	}
}

// Claim: authorize emits exact canonical bytes and fresh nonces, and owner-signed install followed by a separately signed rollback succeeds in fake roots.
func TestVPNOwnerAuthorizationPositive(t *testing.T) {
	f := newVPNFixture(t)
	a, da := f.pkg(t, "a", "tool-a")
	b, db := f.pkg(t, "b", "tool-b")
	if r := f.install(t, a, da); !r.OK {
		t.Fatal(r.Error)
	}
	now := time.Date(2026, 10, 19, 14, 0, 3, 900000000, time.UTC)
	f.s.authorizations.now = func() time.Time { return now }
	req := authorizeVPN(t, f, 501, "install", db)
	parsed, err := parseAuthorization(req.Authorization)
	mustVPN(t, err)
	want := fmt.Sprintf("works.relux.vpn-core.authorize/v1\naction=install\ntarget=vpn-core\ndigest=%s\nnonce=%s\nexpires=2026-10-19T14:02:03Z\n", db, parsed.nonce)
	if string(req.Authorization) != want || len(parsed.nonce) != 64 {
		t.Fatalf("statement=%q", req.Authorization)
	}
	req.Package = b
	if r := f.s.handle(ActionVPNCoreInstall, req, 501); !r.OK {
		t.Fatal(r.Error)
	}
	if pendingVPN(f.s, req.Authorization) {
		t.Fatal("successful nonce remains pending")
	}
	if bytes.Contains(readVPN(t, f.s.audit), []byte(parsed.nonce)) {
		t.Fatal("audit persisted nonce")
	}
	rollback := authorizeVPN(t, f, 501, "rollback", da)
	if bytes.Equal(req.Authorization, rollback.Authorization) {
		t.Fatal("nonce was reused")
	}
	if r := f.s.handle(ActionVPNCoreRollback, rollback, 501); !r.OK || r.VPNCore.Digest != da {
		t.Fatalf("rollback=%+v", r)
	}
}

// Claim: each missing/unsafe pin rejects authorize AND both mutations before effects; default UID zero rejects a normal-user-owned pin.
func TestVPNOwnerPinRefusals(t *testing.T) {
	cases := []struct {
		name, code string
		change     func(*testing.T, *vpnFixture)
	}{
		{"missing", "owner_key_missing", func(t *testing.T, f *vpnFixture) { mustVPN(t, os.Remove(f.s.ownerKey)) }},
		{"symlink", "owner_key_unsafe", func(t *testing.T, f *vpnFixture) {
			dest := f.s.ownerKey + ".real"
			mustVPN(t, os.Rename(f.s.ownerKey, dest))
			mustVPN(t, os.Symlink(dest, f.s.ownerKey))
		}},
		{"mode0644", "owner_key_unsafe", func(t *testing.T, f *vpnFixture) { mustVPN(t, os.Chmod(f.s.ownerKey, 0o644)) }},
		{"wrongUID", "owner_key_unsafe", func(t *testing.T, f *vpnFixture) { f.s.ownerKeyUID = uint32(os.Getuid() + 1) }},
		{"defaultRootUID", "owner_key_unsafe", func(t *testing.T, f *vpnFixture) {
			if os.Getuid() == 0 {
				t.Skip("requires user-owned fixture")
			}
			f.s.ownerKeyUID = newVPNCoreService(501, 20).ownerKeyUID
		}},
		{"nonP256", "owner_key_unsafe", func(t *testing.T, f *vpnFixture) {
			key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			mustVPN(t, err)
			der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
			mustVPN(t, err)
			replacePinVPN(t, f, der)
		}},
		{"garbage", "owner_key_unsafe", func(t *testing.T, f *vpnFixture) { replacePinVPN(t, f, []byte("garbage")) }},
		{"hardlink", "owner_key_unsafe", func(t *testing.T, f *vpnFixture) { mustVPN(t, os.Link(f.s.ownerKey, f.s.ownerKey+".link")) }},
		{"oversize", "owner_key_unsafe", func(t *testing.T, f *vpnFixture) { replacePinVPN(t, f, make([]byte, 1025)) }},
		{"directory", "owner_key_unsafe", func(t *testing.T, f *vpnFixture) {
			mustVPN(t, os.Remove(f.s.ownerKey))
			mustVPN(t, os.Mkdir(f.s.ownerKey, 0o444))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newVPNFixture(t)
			pkg, d := f.pkg(t, "baseline", "tool")
			if r := f.install(t, pkg, d); !r.OK {
				t.Fatal(r.Error)
			}
			req := authorizeVPN(t, f, 501, "install", d)
			req.Package = pkg
			tc.change(t, f)
			refusalUnchangedVPN(t, f, ActionVPNCoreAuthorize, &VPNCoreRequest{Target: "vpn-core", AuthorizeAction: "install", ExpectedDigest: d}, 501, tc.code)
			for _, action := range []Action{ActionVPNCoreInstall, ActionVPNCoreRollback} {
				if action == ActionVPNCoreRollback {
					req.Package = ""
				}
				refusalUnchangedVPN(t, f, action, req, 501, tc.code)
			}
			if !pendingVPN(f.s, req.Authorization) {
				t.Fatal("pin gate consumed nonce")
			}
		})
	}
}
func replacePinVPN(t *testing.T, f *vpnFixture, data []byte) {
	t.Helper()
	mustVPN(t, os.Chmod(f.s.ownerKey, 0o600))
	writeVPN(t, f.s.ownerKey, data)
	mustVPN(t, os.Chmod(f.s.ownerKey, 0o444))
}

// Claim: presence/syntax gates retain nonces, and every known nonce reaching binding/expiry/signature gates is consumed on its specific refusal with no install/plist/launch effects.
func TestVPNOwnerAuthorizationRefusals(t *testing.T) {
	cases := []struct {
		name, code string
		consumed   bool
		change     func(*testing.T, *vpnFixture, *VPNCoreRequest)
	}{
		{"missingAuthorization", "authorization_missing", false, func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) { r.Authorization = nil }},
		{"missingSignature", "authorization_missing", false, func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) { r.Signature = nil }},
		{"extraLine", "authorization_invalid", false, func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			r.Authorization = append(r.Authorization, []byte("extra=x\n")...)
		}},
		{"reordered", "authorization_invalid", false, func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			r.Authorization = []byte(strings.Replace(string(r.Authorization), "action=install\ntarget=vpn-core", "target=vpn-core\naction=install", 1))
		}},
		{"trailingByte", "authorization_invalid", false, func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) { r.Authorization = append(r.Authorization, 'x') }},
		{"uppercaseHex", "authorization_invalid", false, func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			r.Authorization = []byte(strings.Replace(string(r.Authorization), r.ExpectedDigest, strings.ToUpper(r.ExpectedDigest), 1))
		}},
		{"unknown", "authorization_unknown", false, func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			p, err := parseAuthorization(r.Authorization)
			mustVPN(t, err)
			r.Authorization = authorizationBytes(p.action, p.digest, strings.Repeat("0", 64), p.expires)
			r.Signature = signVPNStatement(t, f.key, r.Authorization)
		}},
		{"restarted", "authorization_unknown", true, func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			fresh := newVPNCoreService(501, 20)
			fresh.install = f.s.install
			fresh.plist = f.s.plist
			fresh.audit = f.s.audit
			fresh.ops = f.s.ops
			fresh.ownerKey = f.s.ownerKey
			fresh.ownerKeyUID = f.s.ownerKeyUID
			f.s = fresh
		}},
		{"expired", "authorization_expired", true, func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			p, err := parseAuthorization(r.Authorization)
			mustVPN(t, err)
			f.s.authorizations.now = func() time.Time { return p.expires.Add(time.Second) }
		}},
		{"atExpiry", "authorization_expired", true, func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			p, err := parseAuthorization(r.Authorization)
			mustVPN(t, err)
			f.s.authorizations.now = func() time.Time { return p.expires }
		}},
		{"anotherDigest", "authorization_mismatch", true, func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) { r.ExpectedDigest = strings.Repeat("b", 64) }},
		{"rollbackForInstall", "authorization_mismatch", true, func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			other := authorizeVPN(t, f, 501, "rollback", r.ExpectedDigest)
			r.Authorization = other.Authorization
			r.Signature = other.Signature
		}},
		{"anotherUID", "authorization_mismatch", true, func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			other := authorizeVPN(t, f, 502, "install", r.ExpectedDigest)
			r.Authorization = other.Authorization
			r.Signature = other.Signature
		}},
		{"modifiedIssuedBytes", "authorization_mismatch", true, func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			p, err := parseAuthorization(r.Authorization)
			mustVPN(t, err)
			r.Authorization = authorizationBytes(p.action, p.digest, p.nonce, p.expires.Add(time.Second))
			r.Signature = signVPNStatement(t, f.key, r.Authorization)
		}},
		{"differentKey", "owner_signature_invalid", true, func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			mustVPN(t, err)
			r.Signature = signVPNStatement(t, key, r.Authorization)
		}},
		{"anotherStatement", "owner_signature_invalid", true, func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			r.Signature = signVPNStatement(t, f.key, append(bytes.Clone(r.Authorization), 'x'))
		}},
		{"highS", "owner_signature_invalid", true, func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			var sig struct{ R, S *big.Int }
			_, err := asn1.Unmarshal(r.Signature, &sig)
			mustVPN(t, err)
			sig.S.Sub(f.key.Params().N, sig.S)
			r.Signature, err = asn1.Marshal(sig)
			mustVPN(t, err)
		}},
		{"truncated", "owner_signature_invalid", true, func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) { r.Signature = r.Signature[:len(r.Signature)-1] }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newVPNFixture(t)
			pkg, d := f.pkg(t, "baseline", "tool")
			if r := f.install(t, pkg, d); !r.OK {
				t.Fatal(r.Error)
			}
			req := authorizeVPN(t, f, 501, "install", d)
			req.Package = pkg
			original := bytes.Clone(req.Authorization)
			tc.change(t, f, req)
			if tc.name == "rollbackForInstall" || tc.name == "anotherUID" {
				original = bytes.Clone(req.Authorization)
			}
			refusalUnchangedVPN(t, f, ActionVPNCoreInstall, req, 501, tc.code)
			if pendingVPN(f.s, original) == tc.consumed {
				t.Fatalf("nonce pending=%v, consumed expected=%v", pendingVPN(f.s, original), tc.consumed)
			}
			if tc.consumed {
				refusalUnchangedVPN(t, f, ActionVPNCoreInstall, req, 501, "authorization_unknown")
			}
		})
	}
}

// Claim: a low-S authorization at 119 seconds still installs, and its consumed statement cannot be replayed even after issuing a newer authorization for the same digest.
func TestVPNOwnerAuthorizationReplayAnd119Seconds(t *testing.T) {
	f := newVPNFixture(t)
	now := time.Date(2026, 10, 19, 14, 0, 0, 0, time.UTC)
	f.s.authorizations.now = func() time.Time { return now }
	pkg, d := f.pkg(t, "binary", "tool")
	req := authorizeVPN(t, f, 501, "install", d)
	req.Package = pkg
	now = now.Add(119 * time.Second)
	if r := f.s.handle(ActionVPNCoreInstall, req, 501); !r.OK {
		t.Fatal(r.Error)
	}
	refusalUnchangedVPN(t, f, ActionVPNCoreInstall, req, 501, "authorization_unknown")
	newer := authorizeVPN(t, f, 501, "install", d)
	refusalUnchangedVPN(t, f, ActionVPNCoreInstall, req, 501, "authorization_unknown")
	if pendingVPN(f.s, req.Authorization) || !pendingVPN(f.s, newer.Authorization) {
		t.Fatal("replay changed pending state")
	}
}

// Claim: a known authorization consumed by an existing package-verification failure cannot be retried after fixing the package.
func TestVPNOwnerAuthorizationFailedInstallReplay(t *testing.T) {
	f := newVPNFixture(t)
	pkg, d := f.pkg(t, "binary", "tool")
	req := authorizeVPN(t, f, 501, "install", d)
	req.Package = pkg
	writeVPN(t, filepath.Join(pkg, "vpn-core"), []byte("corrupt"))
	refusalUnchangedVPN(t, f, ActionVPNCoreInstall, req, 501, "file_sha_mismatch")
	writeVPN(t, filepath.Join(pkg, "vpn-core"), []byte("binary"))
	refusalUnchangedVPN(t, f, ActionVPNCoreInstall, req, 501, "authorization_unknown")
	if pendingVPN(f.s, req.Authorization) {
		t.Fatal("failed install kept nonce")
	}
}

// Claim: issuing nine authorizations evicts only the oldest, even with equal clock times; the remaining oldest and newest are still usable.
func TestVPNOwnerAuthorizationCap(t *testing.T) {
	f := newVPNFixture(t)
	f.s.authorizations.now = func() time.Time { return time.Date(2026, 10, 19, 14, 0, 0, 0, time.UTC) }
	pkg, d := f.pkg(t, "binary", "tool")
	var requests []*VPNCoreRequest
	for i := 0; i < 9; i++ {
		r := authorizeVPN(t, f, 501, "install", d)
		r.Package = pkg
		requests = append(requests, r)
	}
	if len(f.s.authorizations.pending) != 8 {
		t.Fatalf("pending=%d", len(f.s.authorizations.pending))
	}
	refusalUnchangedVPN(t, f, ActionVPNCoreInstall, requests[0], 501, "authorization_unknown")
	for _, i := range []int{1, 8} {
		if r := f.s.handle(ActionVPNCoreInstall, requests[i], 501); !r.OK {
			t.Fatal(r.Error)
		}
	}
}

// Claim: invalid authorize action/digest is specifically refused without nonce allocation or installation effects.
func TestVPNOwnerAuthorizeAdmission(t *testing.T) {
	for _, tc := range []struct{ action, digest, code string }{{"status", strings.Repeat("a", 64), "invalid_request"}, {"install", strings.Repeat("A", 64), "invalid_digest"}, {"install", "bad", "invalid_digest"}} {
		t.Run(tc.action+tc.digest, func(t *testing.T) {
			f := newVPNFixture(t)
			refusalUnchangedVPN(t, f, ActionVPNCoreAuthorize, &VPNCoreRequest{Target: "vpn-core", AuthorizeAction: tc.action, ExpectedDigest: tc.digest}, 501, tc.code)
			if len(f.s.authorizations.pending) != 0 {
				t.Fatal("invalid authorize issued nonce")
			}
		})
	}
}

// Claim: rollback also requires presence/syntax and a valid low-S owner signature, consuming a recognized nonce on a signature refusal while preserving both installed versions and plist.
func TestVPNOwnerRollbackAuthorizationEnforced(t *testing.T) {
	for _, kind := range []string{"missing", "malformed", "signature"} {
		t.Run(kind, func(t *testing.T) {
			f := newVPNFixture(t)
			a, da := f.pkg(t, "a", "tool-a")
			b, db := f.pkg(t, "b", "tool-b")
			if r := f.install(t, a, da); !r.OK {
				t.Fatal(r.Error)
			}
			if r := f.install(t, b, db); !r.OK {
				t.Fatal(r.Error)
			}
			req := authorizeVPN(t, f, 501, "rollback", da)
			original := bytes.Clone(req.Authorization)
			code := "authorization_missing"
			switch kind {
			case "missing":
				req.Signature = nil
			case "malformed":
				req.Authorization = append(req.Authorization, 'x')
				code = "authorization_invalid"
			case "signature":
				req.Signature = []byte("bad DER")
				code = "owner_signature_invalid"
			}
			refusalUnchangedVPN(t, f, ActionVPNCoreRollback, req, 501, code)
			if pendingVPN(f.s, original) == (kind == "signature") {
				t.Fatal("rollback consumption state incorrect")
			}
		})
	}
}

// Claim: the exact low-S signature used to construct a high-S counterpart is accepted, while its mathematically equivalent high-S counterpart is specifically refused on an otherwise identical fresh server.
func TestVPNOwnerLowSControl(t *testing.T) {
	f := newVPNFixture(t)
	pkg, d := f.pkg(t, "binary", "tool")
	req := authorizeVPN(t, f, 501, "install", d)
	req.Package = pkg
	parsed, err := parseAuthorization(req.Authorization)
	mustVPN(t, err)
	f.s.authorizations.mu.Lock()
	issued := f.s.authorizations.pending[0]
	f.s.authorizations.mu.Unlock()
	if issued.nonce != parsed.nonce {
		t.Fatal("unexpected issued nonce")
	}
	other := newVPNFixture(t)
	other.s.authorizations.pending = []vpnAuthorization{issued}
	der, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	mustVPN(t, err)
	replacePinVPN(t, other, der)
	high := *req
	var sig struct{ R, S *big.Int }
	_, err = asn1.Unmarshal(req.Signature, &sig)
	mustVPN(t, err)
	sig.S.Sub(f.key.Params().N, sig.S)
	high.Signature, err = asn1.Marshal(sig)
	mustVPN(t, err)
	hash := sha256.Sum256(high.Authorization)
	if !ecdsa.VerifyASN1(&f.key.PublicKey, hash[:], high.Signature) {
		t.Fatal("high-S control is not mathematically valid")
	}
	refusalUnchangedVPN(t, other, ActionVPNCoreInstall, &high, 501, "owner_signature_invalid")
	if pendingVPN(other.s, high.Authorization) {
		t.Fatal("high-S refusal retained nonce")
	}
	if r := f.s.handle(ActionVPNCoreInstall, req, 501); !r.OK {
		t.Fatal("low-S original refused:", r.Error)
	}
}

// Claim: request admission preserves gate precedence: pin safety precedes missing inputs; presence precedes syntax; syntax precedes nonce lookup; binding precedes expiry; expiry precedes signature verification.
func TestVPNOwnerGateOrder(t *testing.T) {
	for _, gate := range []string{"pin", "presence", "syntax", "binding", "expiry"} {
		t.Run(gate, func(t *testing.T) {
			f := newVPNFixture(t)
			pkg, d := f.pkg(t, "binary", "tool")
			req := authorizeVPN(t, f, 501, "install", d)
			req.Package = pkg
			p, err := parseAuthorization(req.Authorization)
			mustVPN(t, err)
			code := ""
			switch gate {
			case "pin":
				mustVPN(t, os.Remove(f.s.ownerKey))
				req.Authorization = nil
				req.Signature = nil
				code = "owner_key_missing"
			case "presence":
				req.Authorization = []byte("malformed")
				req.Signature = nil
				code = "authorization_missing"
			case "syntax":
				f.s.authorizations.pending = nil
				req.Authorization = append(req.Authorization, 'x')
				code = "authorization_invalid"
			case "binding":
				req.ExpectedDigest = strings.Repeat("0", 64)
				f.s.authorizations.now = func() time.Time { return p.expires.Add(time.Second) }
				req.Signature = []byte("bad")
				code = "authorization_mismatch"
			case "expiry":
				f.s.authorizations.now = func() time.Time { return p.expires.Add(time.Second) }
				req.Signature = []byte("bad")
				code = "authorization_expired"
			}
			refusalUnchangedVPN(t, f, ActionVPNCoreInstall, req, 501, code)
			if (gate == "binding" || gate == "expiry") && pendingVPN(f.s, req.Authorization) {
				t.Fatal("late gate retained nonce")
			}
		})
	}
}
