package chromectl

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/mac-infra/internal/browsersession"
)

func TestFormatAutomationErrorPreservesVerifiedScriptExceptions(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node unavailable; generated wrapper execution not exercised")
	}
	for _, message := range []string{"ordinary failure", "feature turned off", "AppleScript parser failed"} {
		t.Run(message, func(t *testing.T) {
			calls := 0
			source := fmt.Sprintf(`(() => { ++globalThis.__runs; throw new Error(%q); })()`, message)
			result, err := browsersession.ExecuteJavaScript(source, "https://example.com", func(wrapped string) (string, error) {
				calls++
				program := `globalThis.location={origin:"https://example.com"};globalThis.document={readyState:"complete"};globalThis.__runs=0;console.log(` + wrapped + `);if(globalThis.__runs!==1)process.exit(42);`
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				out, engineErr := exec.CommandContext(ctx, node, "-e", program).CombinedOutput()
				if engineErr != nil {
					t.Fatalf("generated wrapper failed: %v: %s", engineErr, out)
				}
				return strings.TrimSpace(string(out)), nil
			})
			if !errors.Is(err, browsersession.ErrScriptException) || !strings.Contains(err.Error(), message) {
				t.Fatalf("not a verified page exception: %v", err)
			}
			if calls != 1 || result != (browsersession.ExecutionResult{}) {
				t.Fatalf("calls=%d result=%+v", calls, result)
			}
			for _, diagnostic := range []error{err, fmt.Errorf("run-js: %w", err)} {
				if got := FormatAutomationError(diagnostic); got != diagnostic.Error() {
					t.Fatalf("page exception gained permission advice: %q", got)
				}
			}
		})
	}
}

func TestFormatAutomationErrorKeepsAutomationDenialAdvice(t *testing.T) {
	err := errors.New("JavaScript from Apple Events is turned off")
	got := FormatAutomationError(err)
	if !strings.HasPrefix(got, err.Error()) || !strings.Contains(got, "Chrome blocked JavaScript automation") {
		t.Fatalf("automation denial lost its cause or advice: %q", got)
	}
}
