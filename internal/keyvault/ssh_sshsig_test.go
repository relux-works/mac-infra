package keyvault

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func sshsigBlob(namespace, reserved, algorithm string, hash []byte) []byte {
	return append([]byte(sshsigMagic), ssh.Marshal(struct {
		Namespace, Reserved, Algorithm string
		Hash                           []byte
	}{namespace, reserved, algorithm, hash})...)
}

// sshAuthBlob is the data an SSH client asks an agent to sign for public-key
// authentication (RFC 4252 section 7): it starts with the session identifier.
func sshAuthBlob(key ssh.PublicKey) []byte {
	return ssh.Marshal(struct {
		Session   []byte
		Request   byte
		User      string
		Service   string
		Method    string
		HasSig    bool
		Algorithm string
		Key       []byte
	}{bytes.Repeat([]byte{7}, 32), 50, "git", "ssh-connection", "publickey", true, ssh.KeyAlgoECDSA256, key.Marshal()})
}

// The parser accepts exactly the ssh-keygen -Y sign blob (sha512 as OpenSSH
// sends by default, and sha256); every malformed or foreign variant,
// including an authentication request, is refused.
func TestParseSSHSig(t *testing.T) {
	sum := sha512.Sum512([]byte("tag object"))
	for _, tc := range []struct {
		algorithm string
		hash      []byte
	}{{"sha512", sum[:]}, {"sha256", sum[:32]}} {
		got, err := ParseSSHSig(sshsigBlob("git", "", tc.algorithm, tc.hash))
		if err != nil || got.Namespace != "git" || got.HashAlgorithm != tc.algorithm || !bytes.Equal(got.MessageHash, tc.hash) {
			t.Fatalf("%s control: %+v %v", tc.algorithm, got, err)
		}
	}
	a, _, _ := sshFixture(t)
	valid := sshsigBlob("git", "", "sha512", sum[:])
	for name, data := range map[string][]byte{
		"authentication":     sshAuthBlob(a.identities[0].public),
		"empty":              nil,
		"magic only":         []byte(sshsigMagic),
		"wrong magic":        append([]byte("SSHSIH"), valid[6:]...),
		"truncated":          valid[:len(valid)-1],
		"trailing data":      append(append([]byte(nil), valid...), 0),
		"reserved set":       sshsigBlob("git", "x", "sha512", sum[:]),
		"unknown algorithm":  sshsigBlob("git", "", "md5", sum[:16]),
		"short sha512 hash":  sshsigBlob("git", "", "sha512", sum[:32]),
		"long sha256 hash":   sshsigBlob("git", "", "sha256", sum[:]),
		"empty namespace":    sshsigBlob("", "", "sha512", sum[:]),
		"namespace newline":  sshsigBlob("git\n", "", "sha512", sum[:]),
		"namespace too long": sshsigBlob(strings.Repeat("g", 65), "", "sha512", sum[:]),
	} {
		if _, err := ParseSSHSig(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if !ValidSSHSigNamespace("git") || !ValidSSHSigNamespace("file") || ValidSSHSigNamespace("") || ValidSSHSigNamespace("-git") || ValidSSHSigNamespace("g it") {
		t.Fatal("namespace validation")
	}
}

func sshAuditFile(t *testing.T) (*SSHAuditLog, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := OpenSSHAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	return log, path
}

func sshAuditRecords(t *testing.T, path string) []SSHAuditRecord {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var records []SSHAuditRecord
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var record SSHAuditRecord
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&record); err != nil {
			t.Fatalf("audit line %q: %v", scanner.Text(), err)
		}
		records = append(records, record)
	}
	return records
}

// With --sign-namespace git, real ssh-keygen -Y sign -n git signs through the
// socket and ssh-keygen -Y verify accepts it (positive control). The same
// tool with -n file, an authentication request and a malformed SSHSIG are
// refused without any private operation, and each refusal is audited. The
// audit holds metadata and hash prefixes, never the message or a full hash.
func TestSSHAgentGitNamespaceOnlyWithAudit(t *testing.T) {
	a, store, addr := sshFixture(t)
	if err := a.RequireSSHSigNamespace("git"); err != nil {
		t.Fatal(err)
	}
	log, logPath := sshAuditFile(t)
	a.AuditTo(log)
	socket, _, _ := sshSocket(t, a)
	dir := t.TempDir()
	pub := SSHPublicBytes(t, a)
	key := filepath.Join(dir, "key.pub")
	os.WriteFile(key, pub, 0600)
	message := []byte("object 0123456789abcdef secret-tag-body\n")
	input := filepath.Join(dir, "message")
	os.WriteFile(input, message, 0600)
	env := append(os.Environ(), "SSH_AUTH_SOCK="+socket)

	sshCommand(t, env, nil, "/usr/bin/ssh-keygen", "-Y", "sign", "-f", key, "-n", "git", input)
	allowed := filepath.Join(dir, "allowed_signers")
	os.WriteFile(allowed, append([]byte("release@example.test "), pub...), 0600)
	sshCommand(t, env, message, "/usr/bin/ssh-keygen", "-Y", "verify", "-f", allowed, "-I", "release@example.test", "-n", "git", "-s", input+".sig")
	if len(store.signs) != 1 {
		t.Fatalf("git signature: %d private operations", len(store.signs))
	}

	os.Remove(input + ".sig")
	cmd := exec.Command("/usr/bin/ssh-keygen", "-Y", "sign", "-f", key, "-n", "file", input)
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("file namespace signed: %s", out)
	}
	client := sshClient(t, a)
	sum := sha512.Sum512(message)
	for name, data := range map[string][]byte{
		"authentication": sshAuthBlob(a.identities[0].public),
		"malformed":      sshsigBlob("git", "x", "sha512", sum[:]),
	} {
		if _, err := client.Sign(a.identities[0].public, data); err == nil {
			t.Fatalf("%s request signed", name)
		}
	}
	if len(store.signs) != 1 {
		t.Fatalf("refusals reached the private operation: %d", len(store.signs))
	}

	records := sshAuditRecords(t, logPath)
	if len(records) != 4 {
		t.Fatalf("audit records: %+v", records)
	}
	signed := records[0]
	if signed.Outcome != SSHAuditSigned || signed.Reason != "" || signed.Namespace != "git" || signed.HashAlgorithm != "sha512" ||
		signed.MessageHashPrefix != hex.EncodeToString(sum[:8]) || len(signed.DigestPrefix) != 16 || signed.ClientPID <= 0 ||
		signed.Address != addr.Service+"/"+addr.Purpose || signed.Version != 1 || signed.Fingerprint != ssh.FingerprintSHA256(a.identities[0].public) || signed.Time == "" {
		t.Fatalf("signed record: %+v", signed)
	}
	for i, want := range []struct{ reason, namespace string }{{"namespace", "file"}, {"not_sshsig", ""}, {"not_sshsig", ""}} {
		got := records[i+1]
		if got.Outcome != SSHAuditRefused || got.Reason != want.reason || got.Namespace != want.namespace {
			t.Errorf("refusal %d: %+v", i, got)
		}
	}
	raw, _ := os.ReadFile(logPath)
	if bytes.Contains(raw, message) || bytes.Contains(raw, []byte("secret-tag-body")) || bytes.Contains(raw, []byte(hex.EncodeToString(sum[:]))) {
		t.Fatal("audit log contains the message or a full hash")
	}
	if st, err := os.Stat(logPath); err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("audit log mode: %v %v", st, err)
	}
}

// Without --sign-namespace the agent keeps signing any data for its pinned
// identities (unchanged contract), so the restriction is what refuses above.
func TestSSHAgentUnrestrictedStillSignsAnyNamespace(t *testing.T) {
	a, store, _ := sshFixture(t)
	client := sshClient(t, a)
	sum := sha512.Sum512([]byte("m"))
	for _, data := range [][]byte{sshsigBlob("file", "", "sha512", sum[:]), sshAuthBlob(a.identities[0].public)} {
		sig, err := client.Sign(a.identities[0].public, data)
		if err != nil || a.identities[0].public.Verify(data, sig) != nil {
			t.Fatalf("unrestricted sign: %v", err)
		}
	}
	if len(store.signs) != 2 {
		t.Fatalf("private operations: %d", len(store.signs))
	}
	if a.RequireSSHSigNamespace("") == nil || a.RequireSSHSigNamespace("g it") == nil {
		t.Fatal("invalid restriction accepted")
	}
}

// A signature whose audit record cannot be written is withheld: the client
// gets a failure even though the private operation ran. Control: with a
// working log the same request returns a verifiable signature.
func TestSSHAgentWithholdsSignatureWhenAuditFails(t *testing.T) {
	a, store, _ := sshFixture(t)
	a.RequireSSHSigNamespace("git")
	log, path := sshAuditFile(t)
	a.AuditTo(log)
	client := sshClient(t, a)
	sum := sha512.Sum512([]byte("m"))
	data := sshsigBlob("git", "", "sha512", sum[:])
	sig, err := client.Sign(a.identities[0].public, data)
	if err != nil || a.identities[0].public.Verify(data, sig) != nil {
		t.Fatalf("control: %v", err)
	}
	log.Close()
	if _, err := client.Sign(a.identities[0].public, data); err == nil {
		t.Fatal("signature returned without an audit record")
	}
	if len(store.signs) != 2 || len(sshAuditRecords(t, path)) != 1 {
		t.Fatalf("signs %d", len(store.signs))
	}
}

// The audit log opens only as a private regular file of the caller: new
// files are created 0600 and existing records are kept (append, no
// truncation); relative paths, symlinks, hard links, directories and files
// others can write are refused.
func TestOpenSSHAuditLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	log, err := OpenSSHAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	log.Append(SSHAuditRecord{Outcome: SSHAuditSigned, DigestPrefix: "00"})
	log.Close()
	if log, err = OpenSSHAuditLog(path); err != nil {
		t.Fatal(err)
	}
	log.Append(SSHAuditRecord{Outcome: SSHAuditRefused, DigestPrefix: "01"})
	log.Close()
	if records := sshAuditRecords(t, path); len(records) != 2 || records[0].DigestPrefix != "00" {
		t.Fatalf("reopen truncated or lost records: %+v", records)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	shared := filepath.Join(dir, "shared.jsonl")
	os.WriteFile(shared, nil, 0600)
	os.Chmod(shared, 0620)
	// The symlink target is a clean private file with one link, so only the
	// refusal to follow symlinks can reject it.
	target := filepath.Join(dir, "target.jsonl")
	os.WriteFile(target, nil, 0600)
	link := filepath.Join(dir, "link.jsonl")
	os.Symlink(target, link)
	hard := filepath.Join(dir, "hard.jsonl")
	os.Link(path, hard)
	for name, p := range map[string]string{"relative": "audit.jsonl", "symlink": link, "hard link": hard, "directory": dir, "group-writable": shared} {
		if l, err := OpenSSHAuditLog(p); err == nil {
			l.Close()
			t.Errorf("%s accepted", name)
		}
	}
}

// A request outside the namespace is refused before the confirmation hook
// runs, so it can neither show a dialog nor be granted by one; a git request
// reaches the hook (control).
func TestSSHAgentNamespaceRefusedBeforeConfirmation(t *testing.T) {
	a, store, _ := sshFixture(t)
	a.RequireSSHSigNamespace("git")
	asked := 0
	a.confirm = func(context.Context, SSHConfirmation) error { asked++; return nil }
	client := sshClient(t, a)
	sum := sha512.Sum512([]byte("m"))
	if _, err := client.Sign(a.identities[0].public, sshsigBlob("file", "", "sha512", sum[:])); err == nil || asked != 0 {
		t.Fatalf("file namespace: err %v, hook asked %d", err, asked)
	}
	if _, err := client.Sign(a.identities[0].public, sshsigBlob("git", "", "sha512", sum[:])); err != nil || asked != 1 || len(store.signs) != 1 {
		t.Fatalf("git control: err %v, hook asked %d", err, asked)
	}
}
