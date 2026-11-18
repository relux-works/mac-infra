package javatruststore

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type commandCapture struct {
	args       [][]string
	dirs       []string
	envs       [][]string
	failImport bool
}

func (c *commandCapture) CombinedOutput(_ context.Context, _ string, args []string, dir string, env []string) ([]byte, error) {
	c.args = append(c.args, append([]string(nil), args...))
	c.dirs = append(c.dirs, dir)
	c.envs = append(c.envs, append([]string(nil), env...))
	if len(args) > 0 && args[0] == "-list" && strings.Contains(strings.Join(args, " "), "-storetype JKS") {
		return nil, errors.New("not JKS")
	}
	if len(args) > 0 && args[0] == "-importcert" && c.failImport {
		return nil, errors.New("fixture import failure")
	}
	return nil, nil
}

// Claim: the keytool adapter detects the copied store format, imports only the supplied root file, and confines its Java home and temp settings to output.
func TestKeytoolImporterDetectsAndImportsCopiedStore(t *testing.T) {
	output := t.TempDir()
	store := filepath.Join(output, "truststore")
	root := filepath.Join(output, "root.pem")
	if err := os.WriteFile(store, []byte("fixture cacerts"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root, []byte("fixture root"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JAVA_TOOL_OPTIONS", "-Dfixture.option=1")
	capture := &commandCapture{}
	storeType, err := (KeytoolImporter{Runner: capture}).Import(context.Background(), "/fixture/jdk/bin/keytool", store, root, "fixture-root-pin")
	if err != nil {
		t.Fatal(err)
	}
	if storeType != "PKCS12" || len(capture.args) != 3 {
		t.Fatalf("store type %q, calls %d", storeType, len(capture.args))
	}
	if !strings.Contains(strings.Join(capture.args[2], " "), "-importcert -noprompt -alias fixture-root-pin") || !strings.Contains(strings.Join(capture.args[2], " "), "-file "+root) {
		t.Fatalf("unexpected import args: %q", capture.args[2])
	}
	for index, env := range capture.envs {
		joined := strings.Join(env, "\n")
		if strings.Contains(joined, "fixture.option") || !strings.Contains(joined, "HOME="+output) || !strings.Contains(joined, "TMPDIR="+output) || capture.dirs[index] != output {
			t.Fatalf("command %d escaped isolated environment: dir=%q env=%q", index, capture.dirs[index], joined)
		}
	}
}

// Claim: a failed keytool import returns a stable operational cause without exposing its raw command error.
func TestKeytoolImporterFailureCause(t *testing.T) {
	capture := &commandCapture{failImport: true}
	_, err := (KeytoolImporter{Runner: capture}).Import(context.Background(), "/fixture/jdk/bin/keytool", "/tmp/truststore", "/tmp/root.pem", "fixture-root-pin")
	if Cause(err) != CauseKeytoolFailed || ExitCode(err) != ExitOperational || err.Error() != CauseKeytoolFailed {
		t.Fatalf("import failure = %v, cause=%q exit=%d", err, Cause(err), ExitCode(err))
	}
}

// Claim: PEM parsing accepts a sequence of public fixture certificates and rejects non-certificate input and leading junk.
func TestParseCertificatesPEM(t *testing.T) {
	root := makeCertificate(t, fixtureTime.Add(-time.Hour), fixtureTime.Add(time.Hour), true, "PEM Fixture", "PEM Fixture")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
	certs, err := ParseCertificatesPEM(append(append([]byte("\n"), encoded...), encoded...))
	if err != nil || len(certs) != 2 {
		t.Fatalf("parse fixture PEM: %d certificates, %v", len(certs), err)
	}
	if _, err := x509.ParseCertificate(certs[0].Raw); err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{[]byte("not PEM"), append([]byte("junk"), encoded...), []byte("-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----")} {
		if _, err := ParseCertificatesPEM(input); Cause(err) != CauseMalformedSource {
			t.Errorf("malformed input cause = %q", Cause(err))
		}
	}
}

// Claim: the macOS keychain adapter requests only public PEM certificates with the fixed System.keychain path and is injectable in tests.
func TestSystemKeychainSourceUsesPublicCertificateCommand(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("System.keychain exists only on macOS")
	}
	root := makeCertificate(t, fixtureTime.Add(-time.Hour), fixtureTime.Add(time.Hour), true, "Keychain Fixture", "Keychain Fixture")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
	capture := &publicCertificateCommand{output: encoded}
	certs, err := (SystemKeychainSource{Runner: capture}).Certificates(context.Background())
	if err != nil || len(certs) != 1 {
		t.Fatalf("injected source returned %d certs: %v", len(certs), err)
	}
	if capture.name != "/usr/bin/security" || strings.Join(capture.args, " ") != "find-certificate -a -p /Library/Keychains/System.keychain" {
		t.Fatalf("unexpected public certificate command: %q %q", capture.name, capture.args)
	}
}

type publicCertificateCommand struct {
	name   string
	args   []string
	output []byte
}

func (p *publicCertificateCommand) CombinedOutput(_ context.Context, name string, args []string, _ string, _ []string) ([]byte, error) {
	p.name = name
	p.args = append([]string(nil), args...)
	return append([]byte(nil), p.output...), nil
}
