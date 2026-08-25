package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	productionCLIOnce sync.Once
	productionCLIPath string
	productionCLIErr  error
)

// productionCLIBinary builds the real mac-chrome-session binary once per test
// run so argv assertions observe the production process itself rather than the
// `go test` harness process, whose argv never contains the fetch-file flags.
func productionCLIBinary(t *testing.T) string {
	t.Helper()
	productionCLIOnce.Do(func() {
		dir, err := os.MkdirTemp("", "mac-chrome-session-argv")
		if err != nil {
			productionCLIErr = err
			return
		}
		binary := filepath.Join(dir, "mac-chrome-session")
		if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
			productionCLIErr = err
			t.Logf("build output: %s", out)
			return
		}
		productionCLIPath = binary
	})
	if productionCLIErr != nil {
		t.Fatalf("build production CLI: %v", productionCLIErr)
	}
	return productionCLIPath
}

// readProcessArgv reads the argv of a live process from outside it, the same way
// an operator, a shell history reader, or an agent session transcript would see
// the command. `-ww` disables ps column truncation.
func readProcessArgv(pid int) (string, error) {
	out, err := exec.Command("/bin/ps", "-ww", "-o", "args=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// TestFetchFileKeepsProtectedResourceOutOfProductionCLIArgv is the production-entry
// negative test for the outer privacy boundary. The previous contract declared
// `--resource`, so a protected URL carrying opaque document and sticky
// identifiers existed in the mac-chrome-session process argv before any private
// transport began. This drives the real binary and reads its own argv while it
// is blocked reading the private stdin request.
//
// The blocking read is deliberate: it makes the observation deterministic
// instead of racing process exit, and it needs no browser contact at all.
func TestFetchFileKeepsProtectedResourceOutOfProductionCLIArgv(t *testing.T) {
	binary := productionCLIBinary(t)
	outPath := filepath.Join(t.TempDir(), "result.bin")
	cmd := exec.Command(binary,
		"fetch-file",
		"--window-id", "11",
		"--tab-id", "22",
		"--origin", "https://example.com",
		"--out", outPath,
		"--request-stdin",
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var combined strings.Builder
	cmd.Stdout, cmd.Stderr = &combined, &combined
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	// The resource resolves cross-origin on purpose, so once stdin closes the
	// command fails closed at validation and never reaches Chrome.
	const marker = "argv-probe-fake-document-token"
	if _, err := stdin.Write([]byte(`{"version":1,"resource":"https://other.example/statements?documentId=` + marker + `&stickySession=` + marker + `"}`)); err != nil {
		t.Fatal(err)
	}

	var argv string
	deadline := time.Now().Add(15 * time.Second)
	for {
		argv, err = readProcessArgv(cmd.Process.Pid)
		if err == nil && strings.Contains(argv, "fetch-file") {
			break
		}
		if time.Now().After(deadline) {
			// A failed or empty read is not a legitimate absence of the marker.
			t.Fatalf("could not read the production CLI argv, so absence proves nothing: err=%v argv=%q", err, argv)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Positive control: the capture must be the production command line itself.
	for _, required := range []string{"mac-chrome-session", "fetch-file", "--request-stdin", "--out", "--origin"} {
		if !strings.Contains(argv, required) {
			t.Fatalf("ps did not observe the production fetch-file argv (%q missing); the leak check would be vacuous: %q", required, argv)
		}
	}
	for _, forbidden := range []string{marker, "documentId", "stickySession", "other.example", "--resource", "/statements"} {
		if strings.Contains(argv, forbidden) {
			t.Fatalf("mac-chrome-session process argv leaked %q: %q", forbidden, argv)
		}
	}

	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("cross-origin resource was not refused: err=%v out=%s", err, combined.String())
	}
	if strings.Contains(combined.String(), marker) || strings.Contains(combined.String(), "other.example") {
		t.Fatalf("refusal echoed the protected resource: %s", combined.String())
	}
	if _, statErr := os.Stat(outPath); !os.IsNotExist(statErr) {
		t.Fatalf("refused invocation published output: %v", statErr)
	}
}

// TestFetchFileProductionCLIRejectsResourceFlag proves the leaking argv contract
// is removed rather than merely unused by the documented workflow.
func TestFetchFileProductionCLIRejectsResourceFlag(t *testing.T) {
	binary := productionCLIBinary(t)
	outPath := filepath.Join(t.TempDir(), "result.bin")
	const marker = "removed-flag-fake-token"
	cmd := exec.Command(binary,
		"fetch-file",
		"--window-id", "11",
		"--tab-id", "22",
		"--origin", "https://example.com",
		"--resource", "/statements?documentId="+marker,
		"--out", outPath,
		"--request-stdin",
	)
	cmd.Stdin = strings.NewReader(`{"version":1,"resource":"/statements"}`)
	out, err := cmd.CombinedOutput()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 2 {
		t.Fatalf("--resource was accepted by the production CLI: err=%v out=%s", err, out)
	}
	if strings.Contains(string(out), marker) {
		t.Fatalf("refusal echoed the resource value: %s", out)
	}
	if _, statErr := os.Stat(outPath); !os.IsNotExist(statErr) {
		t.Fatalf("refused invocation published output: %v", statErr)
	}
}

// TestUploadKeepsSourcePathsOutOfProductionCLIArgv drives the real upload
// entry while its bounded request is blocked on private stdin. The source path
// must exist only in that pipe: argv is durable process/session evidence and
// is outside the explicitly authorized native file boundary.
func TestUploadKeepsSourcePathsOutOfProductionCLIArgv(t *testing.T) {
	binary := productionCLIBinary(t)
	cmd := exec.Command(binary,
		"upload",
		"--window-id", "11",
		"--tab-id", "22",
		"--origin", "https://example.com",
		"--human-authorized",
		"--request-stdin",
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var combined strings.Builder
	cmd.Stdout, cmd.Stderr = &combined, &combined
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	const marker = "argv-probe-private-upload-source.pdf"
	const sourcePath = "/private/task-scoped/" + marker
	request := `{"version":1,"inputSelector":"input[type=file]","paths":["` + sourcePath + `"],"allowedExtensions":[".pdf"],"maxFileBytes":1024,"maxTotalBytes":1024}`
	if _, err := stdin.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}

	var argv string
	deadline := time.Now().Add(15 * time.Second)
	for {
		argv, err = readProcessArgv(cmd.Process.Pid)
		if err == nil && strings.Contains(argv, "upload") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("could not read the production upload argv, so path absence proves nothing: err=%v argv=%q", err, argv)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, required := range []string{"mac-chrome-session", "upload", "--window-id", "--tab-id", "--origin", "--human-authorized", "--request-stdin"} {
		if !strings.Contains(argv, required) {
			t.Fatalf("ps did not observe the production upload argv (%q missing); the leak check would be vacuous: %q", required, argv)
		}
	}
	for _, forbidden := range []string{marker, sourcePath, "/private/task-scoped", "--path", "--file"} {
		if strings.Contains(argv, forbidden) {
			t.Fatalf("mac-chrome-session upload argv leaked %q: %q", forbidden, argv)
		}
	}

	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("unavailable private source was not refused: err=%v out=%s", err, combined.String())
	}
	if strings.Contains(combined.String(), marker) || strings.Contains(combined.String(), sourcePath) {
		t.Fatalf("upload refusal echoed the private source path: %s", combined.String())
	}
}
