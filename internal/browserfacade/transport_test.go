package browserfacade

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/browserquery"
	"github.com/relux-works/mac-infra/internal/browsersession"
)

type captureRunner struct {
	command string
	args    []string
	output  string
}

func TestExecRunnerProjectsEveryTransportFailureToTypedGenericDetail(t *testing.T) {
	command := filepath.Join(t.TempDir(), "browser-transport")
	if err := os.WriteFile(command, []byte("#!/bin/sh\nprintf '%s\\n' 'diagnostic account detail' >&2\nexit 9\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := (ExecRunner{}).Run(context.Background(), command)
	if ErrorCode(err) != "TRANSPORT_FAILED" {
		t.Fatalf("error=%v code=%s", err, ErrorCode(err))
	}
	if strings.Contains(err.Error(), "diagnostic") || strings.Contains(err.Error(), "account") {
		t.Fatalf("raw transport detail escaped typed projection: %v", err)
	}
}

func (r *captureRunner) Run(_ context.Context, command string, args ...string) (string, error) {
	r.command = command
	r.args = append([]string(nil), args...)
	return r.output, nil
}

func TestCLITransportUsesSafariExactWindowOriginWithoutInventedTabOrSecretSource(t *testing.T) {
	adapter := testAdapter("none", 1)
	adapter.Browser = browsersession.BrowserSafari
	adapter.Target = browsersession.Target{Browser: browsersession.BrowserSafari, WindowID: "44", Origin: "https://shop.example"}
	runner := &captureRunner{output: `{"matched":1,"skip":0,"take":1,"returned":1,"items":[{"id":"1","title":"Lamp"}]}`}
	response, err := (CLITransport{Runner: runner}).Extract(context.Background(), adapter, browserquery.Query{Fields: []string{"id", "title"}, Take: 1})
	if err != nil || response.Returned != 1 {
		t.Fatalf("response=%#v err=%v", response, err)
	}
	joined := strings.Join(runner.args, " ")
	if runner.command != "mac-safari-session" || !strings.Contains(joined, "run-js --window-id 44 --origin https://shop.example --script") || strings.Contains(joined, "--tab-id") {
		t.Fatalf("command=%s args=%v", runner.command, runner.args)
	}
	for _, forbidden := range browsersession.BlockedJavaScriptTokens() {
		if strings.Contains(strings.ToLower(joined), forbidden) {
			t.Fatalf("Safari extraction source contains forbidden token %q", forbidden)
		}
	}
}

func TestCLITransportUsesChromeExtractorAndExactTargetThenEvaluatesGuardedSource(t *testing.T) {
	adapter := testAdapter("none", 1)
	runner := &captureRunner{output: `{"matched":1,"skip":0,"take":1,"returned":1,"items":[{"id":"1"}]}`}
	response, err := (CLITransport{Runner: runner}).Extract(context.Background(), adapter, browserquery.Query{Fields: []string{"id"}, Take: 1})
	if err != nil || response.Returned != 1 {
		t.Fatalf("response=%#v err=%v", response, err)
	}
	joined := strings.Join(runner.args, " ")
	for _, want := range []string{"extract", "--window-id 11", "--tab-id 22", "--origin https://shop.example", "--fields id", "--take 1"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("Chrome extractor args missing %q: %v", want, runner.args)
		}
	}
	if runner.command != "mac-chrome-session" {
		t.Fatalf("command=%s", runner.command)
	}

	runner.output = `{"advanced":true}`
	value, err := (CLITransport{Runner: runner}).Evaluate(context.Background(), adapter, `JSON.stringify({advanced:true})`)
	if err != nil || value != `{"advanced":true}` {
		t.Fatalf("value=%q err=%v", value, err)
	}
	joined = strings.Join(runner.args, " ")
	if !strings.Contains(joined, "run-js --window-id 11 --tab-id 22 --origin https://shop.example --script") {
		t.Fatalf("Chrome evaluate args=%v", runner.args)
	}
}

func TestExecRunnerRedactsAuthorizationAndSecretURLFromFailure(t *testing.T) {
	bin := t.TempDir()
	path := filepath.Join(bin, "fake-browser")
	body := `#!/bin/sh
printf '%s\n' 'Authorization: Bearer should-never-escape https://example.com/callback?code=topsecret#opaque' >&2
exit 7
`
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	_, err := (ExecRunner{}).Run(context.Background(), "fake-browser")
	if err == nil {
		t.Fatal("secret-bearing transport failure unexpectedly passed")
	}
	message := err.Error()
	for _, forbidden := range []string{"should-never-escape", "topsecret", "opaque", "Bearer "} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("transport error leaked %q: %s", forbidden, message)
		}
	}
}
