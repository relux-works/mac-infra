package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Claim: real setup argument selection bundles the probe with the metadata CLI,
// selects no keyvault/browser tools, and accepts the probe independently, without installing anything.
func TestToolSecretSetupSelection(t *testing.T) {
	b, err := os.ReadFile("setup.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	end := strings.Index(text, "if ! command -v go")
	if end < 0 {
		t.Fatal("setup preflight boundary missing")
	}
	script := text[:end] + "\nfor name in \"${ALL_BINARIES[@]}\"; do\n if selected \"$name\"; then echo \"$name\"; fi\ndone\n"
	path := filepath.Join(t.TempDir(), "selection.sh")
	if err = os.WriteFile(path, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		want []string
	}{{"mac-tool-secret", []string{"mac-tool-secret", "mac-tool-secret-probe"}}, {"mac-tool-secret-probe", []string{"mac-tool-secret-probe"}}, {"mac-load-profile", []string{"mac-load-profile"}}} {
		out, e := exec.Command("/bin/bash", path, "--only", tc.name).CombinedOutput()
		if e != nil {
			t.Fatalf("selection: %v %s", e, out)
		}
		if got := strings.Fields(string(out)); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s selects %v", tc.name, got)
		}
	}
	for _, required := range []string{`for name in mac-tool-secret mac-tool-secret-probe; do`, `-o "$STAGE_DIR/mac-tool-secret" ./cmd/mac-tool-secret`, `-o "$STAGE_DIR/mac-tool-secret-probe" ./cmd/mac-tool-secret-probe`, `--identifier "works.relux.mac-infra.$name"`, `ln -sf "$BUILD_DIR/$name" "$BIN_DIR/$name"`} {
		if !strings.Contains(text, required) {
			t.Errorf("missing build/sign/link wiring %s", required)
		}
	}
}
