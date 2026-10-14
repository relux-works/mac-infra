package keyvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHMaxPacket bounds both allocation and the amount of data signed per request.
const SSHMaxPacket = 256 * 1024
const sshFailure = 5

// SSHConfirmation is sent to an explicitly configured executable on stdin.
// It contains public metadata and a digest, never the client's message.
type SSHConfirmation struct {
	Address     string `json:"address"`
	Version     int    `json:"version"`
	Fingerprint string `json:"fingerprint"`
	SHA256      string `json:"sha256"`
}

// SSHConfirmHook executes a fixed absolute executable without a shell. Exit 0
// grants this use; every other outcome refuses it. Output is always discarded.
func SSHConfirmHook(path string, args []string, timeout time.Duration) (func(context.Context, SSHConfirmation) error, error) {
	if !filepath.IsAbs(path) || timeout <= 0 || timeout > time.Minute {
		return nil, errors.New("confirmation requires an absolute executable and timeout in (0, 1m]")
	}
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
		return nil, errors.New("confirmation executable is unavailable")
	}
	args = append([]string(nil), args...)
	return func(ctx context.Context, req SSHConfirmation) error {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		data, _ := json.Marshal(req)
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.Stdin = bytes.NewReader(data)
		cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
		cmd.WaitDelay = time.Second
		if cmd.Run() != nil {
			return errors.New("confirmation refused")
		}
		if ctx.Err() != nil {
			return errors.New("confirmation refused")
		}
		return nil
	}, nil
}

type sshIdentity struct {
	address Address
	key     Key
	public  ssh.PublicKey
}

// SSHAgent only exposes explicit, version-pinned key records. Its only
// private operation is Manager.Sign, which rechecks record policy on each use.
// All requests are serialized, including confirmation and Security.framework.
type SSHAgent struct {
	manager    *Manager
	identities []sshIdentity
	confirm    func(context.Context, SSHConfirmation) error
	mu         sync.Mutex
}

func NewSSHAgent(manager *Manager, addresses []Address, confirm func(context.Context, SSHConfirmation) error) (*SSHAgent, error) {
	if manager == nil || len(addresses) == 0 || len(addresses) > 32 {
		return nil, errors.New("select between 1 and 32 pinned key records")
	}
	a := &SSHAgent{manager: manager, confirm: confirm}
	seen := map[string]bool{}
	for _, addr := range addresses {
		parsed, err := ParseAddress(addr.Service+"/"+addr.Purpose, addr.Kind, addr.Version)
		if err != nil || parsed.Kind != KindKey || parsed.Version < 1 {
			return nil, errors.New("SSH identities require a key address and explicit positive version")
		}
		key, err := manager.Describe(parsed)
		if err != nil {
			return nil, err
		}
		if err := manager.authorize(key, OperationSign); err != nil {
			return nil, err
		}
		_, pub, err := ParseSPKI(key.SPKI)
		if err != nil {
			return nil, errors.New("SSH identity has no valid P-256 public key")
		}
		public, err := ssh.NewPublicKey(pub)
		if err != nil {
			return nil, errors.New("SSH identity has no valid P-256 public key")
		}
		if seen[string(public.Marshal())] {
			return nil, errors.New("duplicate SSH identity")
		}
		seen[string(public.Marshal())] = true
		a.identities = append(a.identities, sshIdentity{parsed, key, public})
	}
	return a, nil
}

// SSHPublicKey renders a public-only OpenSSH identity for IdentityFile,
// user.signingkey and allowed_signers. It never accesses private material.
func SSHPublicKey(spki []byte) ([]byte, error) {
	_, pub, err := ParseSPKI(spki)
	if err != nil {
		return nil, err
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return ssh.MarshalAuthorizedKey(key), nil
}

// ServeConn implements the closed subset of the OpenSSH agent protocol:
// REQUEST_IDENTITIES(11) and SIGN_REQUEST(13). Every other operation,
// including mutation, lock, smartcard and extensions, receives FAILURE(5).
// Forwarded connections receive the exact same subset and no export path.
func (a *SSHAgent) ServeConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	for {
		conn.SetDeadline(time.Now().Add(2 * time.Minute))
		var head [4]byte
		if _, err := io.ReadFull(conn, head[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(head[:])
		if n == 0 || n > SSHMaxPacket {
			return
		}
		packet := make([]byte, int(n))
		if _, err := io.ReadFull(conn, packet); err != nil {
			return
		}
		response := a.handleSSH(ctx, packet)
		binary.BigEndian.PutUint32(head[:], uint32(len(response)))
		if _, err := conn.Write(append(head[:], response...)); err != nil {
			return
		}
	}
}

func (a *SSHAgent) handleSSH(ctx context.Context, packet []byte) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx.Err() != nil || len(packet) == 0 {
		return []byte{sshFailure}
	}
	switch packet[0] {
	case 11:
		if len(packet) != 1 {
			return []byte{sshFailure}
		}
		response := []byte{12, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(response[1:], uint32(len(a.identities)))
		for _, id := range a.identities {
			response = append(response, ssh.Marshal(struct {
				Blob    []byte
				Comment string
			}{id.public.Marshal(), id.address.String()})...)
		}
		return response
	case 13:
		var req struct {
			Key   []byte
			Data  []byte
			Flags uint32
		}
		if ssh.Unmarshal(packet[1:], &req) != nil || req.Flags != 0 {
			return []byte{sshFailure}
		}
		for _, id := range a.identities {
			if !bytes.Equal(req.Key, id.public.Marshal()) {
				continue
			}
			digest := sha256.Sum256(req.Data)
			if a.confirm != nil && a.confirm(ctx, SSHConfirmation{id.address.Service + "/" + id.address.Purpose, id.address.Version, ssh.FingerprintSHA256(id.public), hex.EncodeToString(digest[:])}) != nil {
				return []byte{sshFailure}
			}
			if ctx.Err() != nil {
				return []byte{sshFailure}
			}
			// Recheck the pinned public half before private use, then bind the
			// returned signature to that same identity before emitting it.
			current, err := a.manager.Describe(id.address)
			if err != nil || !bytes.Equal(current.SPKI, id.key.SPKI) {
				return []byte{sshFailure}
			}
			result, err := a.manager.Sign(id.address, digest[:])
			if ctx.Err() != nil || err != nil || !bytes.Equal(result.Key.SPKI, id.key.SPKI) {
				return []byte{sshFailure}
			}
			ok, err := VerifyDigest(id.key.SPKI, digest[:], result.Signature)
			if err != nil || !ok {
				return []byte{sshFailure}
			}
			// SSH ECDSA signatures carry two mpints, not ASN.1 DER.
			sig := ssh.Signature{Format: ssh.KeyAlgoECDSA256, Blob: ssh.Marshal(struct{ R, S *big.Int }{result.Signature.R, result.Signature.S})}
			return append([]byte{14}, ssh.Marshal(struct{ Signature []byte }{ssh.Marshal(sig)})...)
		}
	}
	return []byte{sshFailure}
}

// ListenSSH creates a 0600 Unix socket in an owned 0700 directory. It
// never removes or replaces any pre-existing path, including stale sockets.
func ListenSSH(path string) (*net.UnixListener, func(), error) {
	if !filepath.IsAbs(path) {
		return nil, nil, errors.New("SSH socket path must be absolute")
	}
	dir := filepath.Dir(path)
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return nil, nil, errors.New("cannot create private SSH socket directory")
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return nil, nil, errors.New("SSH socket directory must be a real owned 0700 directory")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return nil, nil, errors.New("SSH socket directory has a different owner")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return nil, nil, errors.New("SSH socket path already exists or cannot be inspected")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, nil, errors.New("cannot bind SSH socket")
	}
	listener.SetUnlinkOnClose(false)
	created, err := os.Lstat(path)
	cleanup := func() {
		listener.Close()
		current, e := os.Lstat(path)
		if e == nil && created != nil && os.SameFile(created, current) {
			os.Remove(path)
		}
	}
	if err != nil {
		cleanup()
		return nil, nil, errors.New("cannot inspect SSH socket")
	}
	if err := os.Chmod(path, 0600); err != nil {
		cleanup()
		return nil, nil, errors.New("cannot restrict SSH socket")
	}
	return listener, cleanup, nil
}

// Serve accepts a bounded number of clients. Cancellation closes the
// listener and every client and removes only the socket this process made.
// An in-flight Security.framework call is not interruptible; no further
// request is signed after cancellation is observed.
func (a *SSHAgent) Serve(ctx context.Context, listener *net.UnixListener) error {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	slots := make(chan struct{}, 16)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
		case <-done:
		}
	}()
	defer wg.Wait()
	defer cancel()
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("SSH listener stopped")
		}
		select {
		case slots <- struct{}{}:
			wg.Add(1)
			go func() { defer wg.Done(); defer func() { <-slots }(); a.serveSSHPeer(ctx, conn, uint32(os.Getuid())) }()
		default:
			conn.Close()
		}
	}
}

// serveSSHPeer enforces a second authority boundary independent of mode bits:
// only a kernel-attested connection from the agent owner's UID is served.
// Credential retrieval failure closes the peer without protocol output.
func (a *SSHAgent) serveSSHPeer(ctx context.Context, conn *net.UnixConn, ownerUID uint32) {
	uid, err := sshPeerUID(conn)
	if err != nil || uid != ownerUID {
		conn.Close()
		return
	}
	a.ServeConn(ctx, conn)
}
