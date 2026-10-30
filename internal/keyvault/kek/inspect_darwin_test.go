//go:build darwin && cgo

package kek

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

// fixtureClient connects to the socket named by its first argument and
// waits for the server to close the connection.
const fixtureClient = `package main

import (
	"net"
	"os"
)

func main() {
	c, err := net.Dial("unix", os.Args[1])
	if err != nil {
		os.Exit(1)
	}
	buf := make([]byte, 1)
	c.Read(buf)
}
`

const getTaskAllow = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>
`

// buildSigned builds the fixture client once per test and signs a copy per
// variant with codesign's ad-hoc identity (no Keychain is used).
func buildSigned(t *testing.T, dir, name string, signArgs ...string) string {
	t.Helper()
	src := filepath.Join(dir, "src")
	if _, err := os.Stat(filepath.Join(src, "client")); os.IsNotExist(err) {
		os.MkdirAll(src, 0o700)
		os.WriteFile(filepath.Join(src, "main.go"), []byte(fixtureClient), 0o600)
		os.WriteFile(filepath.Join(src, "go.mod"), []byte("module fixture\n\ngo 1.25\n"), 0o600)
		cmd := exec.Command("go", "build", "-o", "client", ".")
		cmd.Dir = src
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build fixture: %v\n%s", err, out)
		}
	}
	path := filepath.Join(dir, name)
	data, _ := os.ReadFile(filepath.Join(src, "client"))
	os.WriteFile(path, data, 0o700)
	args := append([]string{"--force", "--sign", "-", "--identifier", "works.relux.kek-fixture." + name}, signArgs...)
	if out, err := exec.Command("/usr/bin/codesign", append(args, path)...).CombinedOutput(); err != nil {
		t.Fatalf("codesign %s: %v\n%s", name, err, out)
	}
	return path
}

var cdhashLine = regexp.MustCompile(`(?m)^CDHash=([0-9a-f]{40})$`)

func codesignCDHash(t *testing.T, path string) string {
	t.Helper()
	out, _ := exec.Command("/usr/bin/codesign", "-dvvv", path).CombinedOutput()
	m := cdhashLine.FindSubmatch(out)
	if m == nil {
		t.Fatalf("no CDHash for %s:\n%s", path, out)
	}
	return string(m[1])
}

// peerOf runs the binary as a client of a fresh socket and identifies it
// from the server side by audit token.
func peerOf(t *testing.T, dir, binary string) (CodeIdentity, error) {
	t.Helper()
	sock := filepath.Join(dir, "p.sock")
	os.Remove(sock)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	cmd := exec.Command(binary, sock)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	conn, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return CodeInspector{}.Peer(conn)
}

// The inspector reads what codesign wrote: the cdhash codesign prints, the
// hardened-runtime and library-validation flags, and get-task-allow, both
// for a file and for the same binary running as a socket peer. A copy with
// one byte changed after signing is not valid. The runtime,library variant
// without the entitlement is the positive control.
func TestCodeInspectorReadsSignatures(t *testing.T) {
	dir, err := os.MkdirTemp("", "ki")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ents := filepath.Join(dir, "gta.plist")
	os.WriteFile(ents, []byte(getTaskAllow), 0o600)
	variants := []struct {
		name  string
		args  []string
		want  CodeIdentity
		bound bool
	}{
		{"hardened", []string{"--options", "runtime,library"}, CodeIdentity{Valid: true, Runtime: true, LibraryValidation: true}, true},
		{"plain", nil, CodeIdentity{Valid: true}, false},
		{"runtime-only", []string{"--options", "runtime"}, CodeIdentity{Valid: true, Runtime: true}, false},
		{"debuggable", []string{"--options", "runtime,library", "--entitlements", ents}, CodeIdentity{Valid: true, Runtime: true, LibraryValidation: true, GetTaskAllow: true}, false},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			path := buildSigned(t, dir, v.name, v.args...)
			v.want.CDHash = codesignCDHash(t, path)
			file, err := CodeInspector{}.File(path)
			if err != nil || file != v.want {
				t.Fatalf("file = %+v, %v; want %+v", file, err, v.want)
			}
			if (file.Problem() == "") != v.bound {
				t.Fatalf("problem %q for %s", file.Problem(), v.name)
			}
			peer, err := peerOf(t, dir, path)
			if err != nil || peer != v.want {
				t.Fatalf("peer = %+v, %v; want %+v", peer, err, v.want)
			}
		})
	}
	t.Run("changed after signing", func(t *testing.T) {
		path := buildSigned(t, dir, "changed", "--options", "runtime,library")
		data, _ := os.ReadFile(path)
		data[len(data)/2] ^= 1
		os.WriteFile(path, data, 0o700)
		file, err := CodeInspector{}.File(path)
		if err == nil && file.Valid {
			t.Fatalf("a changed binary is valid: %+v", file)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		path := buildSigned(t, dir, "target", "--options", "runtime,library")
		link := filepath.Join(dir, "link")
		os.Symlink(path, link)
		if id, err := (CodeInspector{}).File(link); err == nil {
			t.Fatalf("a symlink was identified: %+v", id)
		}
	})
}
