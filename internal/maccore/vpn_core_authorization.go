package maccore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const vpnAuthorizationDomain = "works.relux.vpn-core.authorize/v1"

// ReadVPNCoreInput snapshots a bounded regular file without following its final
// symlink. O_NONBLOCK also prevents a substituted FIFO from blocking the CLI.
func ReadVPNCoreInput(path string, limit int64) ([]byte, error) {
	file, err := openVPNCoreInput(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("expected regular file of at most %d bytes", limit)
	}
	return readVPNCoreBounded(file, limit)
}

func openVPNCoreInput(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// ParseOwnerPublicKey admits only DER SubjectPublicKeyInfo for P-256.
func ParseOwnerPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, err
	}
	public, ok := key.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		return nil, fmt.Errorf("owner key must be P-256 SPKI DER")
	}
	// The parser tolerates extra fields; only the exact canonical encoding of
	// the key is a pin, so two byte strings never pin the same key.
	if canonical, err := x509.MarshalPKIXPublicKey(public); err != nil || !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("owner key must be canonical P-256 SPKI DER")
	}
	return public, nil
}

func readOwnerPublicKey(path string, ownerUID uint32) (*ecdsa.PublicKey, []byte, error) {
	file, err := openVPNCoreInput(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, vpnRefuse("owner_key_missing", "owner key is not pinned")
		}
		return nil, nil, vpnRefuse("owner_key_unsafe", "cannot safely open owner key")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return nil, nil, vpnRefuse("owner_key_unsafe", "cannot inspect owner key")
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o444 || stat.Uid != ownerUID || stat.Nlink != 1 || stat.Size > 1024 {
		return nil, nil, vpnRefuse("owner_key_unsafe", "owner key metadata is unsafe")
	}
	data, err := readVPNCoreBounded(file, 1024)
	if err != nil {
		return nil, nil, vpnRefuse("owner_key_unsafe", "cannot read bounded owner key")
	}
	public, err := ParseOwnerPublicKey(data)
	if err != nil {
		return nil, nil, vpnRefuse("owner_key_unsafe", "owner key must be P-256 SPKI DER")
	}
	return public, data, nil
}

type vpnAuthorization struct {
	uid                           int
	action, target, digest, nonce string
	expires                       time.Time // printed wall-clock expiry
	issued                        time.Time // clock reading at issue, monotonic in production
	lifetime                      time.Duration
	statement                     []byte
}

type vpnAuthorizations struct {
	mu      sync.Mutex
	pending []vpnAuthorization // issuance order, oldest first, bounded to eight
	now     func() time.Time
	// elapsed measures time since issue. The default subtracts two clock
	// readings, which Go does on the monotonic clock in production, so a
	// wall-clock change neither extends nor shortens an authorization.
	elapsed func(issued time.Time) time.Duration
}

func (a *vpnAuthorizations) since(issued time.Time) time.Duration {
	if a.elapsed != nil {
		return a.elapsed(issued)
	}
	return a.clock().Sub(issued)
}

func (a *vpnAuthorizations) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

func authorizationBytes(action, digest, nonce string, expires time.Time) []byte {
	return []byte(fmt.Sprintf("%s\naction=%s\ntarget=vpn-core\ndigest=%s\nnonce=%s\nexpires=%s\n", vpnAuthorizationDomain, action, digest, nonce, expires.UTC().Format(time.RFC3339)))
}

func parseAuthorization(data []byte) (vpnAuthorization, error) {
	var a vpnAuthorization
	if len(data) > 4096 {
		return a, vpnRefuse("authorization_invalid", "authorization exceeds limit")
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) != 7 || lines[0] != vpnAuthorizationDomain || lines[2] != "target=vpn-core" || lines[6] != "" {
		return a, vpnRefuse("authorization_invalid", "invalid statement layout")
	}
	a.action = strings.TrimPrefix(lines[1], "action=")
	a.target = "vpn-core"
	a.digest = strings.TrimPrefix(lines[3], "digest=")
	a.nonce = strings.TrimPrefix(lines[4], "nonce=")
	var err error
	a.expires, err = time.Parse("2006-01-02T15:04:05Z", strings.TrimPrefix(lines[5], "expires="))
	if err != nil || (a.action != "install" && a.action != "rollback") || !validVPNDigest(a.digest) || !validVPNDigest(a.nonce) || !bytes.Equal(data, authorizationBytes(a.action, a.digest, a.nonce, a.expires)) {
		return a, vpnRefuse("authorization_invalid", "noncanonical statement")
	}
	return a, nil
}

func (s *vpnCoreService) issueAuthorization(uid int, action, digest string) ([]byte, error) {
	s.authorizations.mu.Lock()
	defer s.authorizations.mu.Unlock()
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	issued := s.authorizations.clock()
	expires := issued.UTC().Truncate(time.Second).Add(120 * time.Second)
	// The deadline never falls after the printed expiry: the lifetime is the
	// wall distance to it at issue (119-120 s), measured monotonically.
	a := vpnAuthorization{uid: uid, action: action, target: "vpn-core", digest: digest, nonce: hex.EncodeToString(nonce[:]), expires: expires, issued: issued, lifetime: expires.Sub(issued.UTC())}
	a.statement = authorizationBytes(action, digest, a.nonce, a.expires)
	if len(s.authorizations.pending) == 8 {
		s.authorizations.pending = s.authorizations.pending[1:]
	}
	s.authorizations.pending = append(s.authorizations.pending, a)
	return bytes.Clone(a.statement), nil
}

func (s *vpnCoreService) authorizeMutation(uid int, action Action, req *VPNCoreRequest) error {
	// Gate order is part of the protocol: key, presence, syntax, single-use
	// binding/expiry, then owner signature. None of these stages install bytes.
	public, _, err := readOwnerPublicKey(s.ownerKey, s.ownerKeyUID)
	if err != nil {
		return err
	}
	if len(req.Authorization) == 0 || len(req.Signature) == 0 {
		return vpnRefuse("authorization_missing", "authorization and signature are required")
	}
	parsed, err := parseAuthorization(req.Authorization)
	if err != nil {
		return err
	}
	s.authorizations.mu.Lock()
	index := -1
	var issued vpnAuthorization
	for i, pending := range s.authorizations.pending {
		if pending.nonce == parsed.nonce {
			index, issued = i, pending
			break
		}
	}
	if index < 0 {
		s.authorizations.mu.Unlock()
		return vpnRefuse("authorization_unknown", "nonce is not pending")
	}
	s.authorizations.pending = append(s.authorizations.pending[:index], s.authorizations.pending[index+1:]...)
	elapsed := s.authorizations.since(issued.issued)
	s.authorizations.mu.Unlock()
	if issued.uid != uid || issued.action != strings.TrimPrefix(string(action), "vpn_core_") || issued.target != req.Target || issued.digest != req.ExpectedDigest || !bytes.Equal(issued.statement, req.Authorization) {
		return vpnRefuse("authorization_mismatch", "statement does not match issued request binding")
	}
	if elapsed < 0 || elapsed >= issued.lifetime {
		return vpnRefuse("authorization_expired", "authorization expired")
	}
	var signature struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(req.Signature, &signature)
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(public.Params().N), 1)
	hash := sha256.Sum256(req.Authorization)
	if len(req.Signature) > 4096 || err != nil || len(rest) != 0 || signature.R == nil || signature.S == nil || signature.S.Sign() <= 0 || signature.S.Cmp(halfOrder) > 0 || !ecdsa.VerifyASN1(public, hash[:], req.Signature) {
		return vpnRefuse("owner_signature_invalid", "owner signature must verify as P-256 DER low-S")
	}
	return nil
}
