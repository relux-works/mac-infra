package browsersession

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const javaScriptCorePath = "/System/Library/Frameworks/JavaScriptCore.framework/Versions/Current/Helpers/jsc"
const expressionFramePrefix = "(() => { "
const expressionFrameSuffix = " })();"

func expressionFrame(source string) string {
	return expressionFramePrefix + "return (\n" + source + "\n  );" + expressionFrameSuffix
}

func checkExpressionFrame(frame string) error {
	return (expressionSyntaxChecker{path: javaScriptCorePath, timeout: 2 * time.Second}).check(frame)
}

type expressionSyntaxChecker struct {
	path    string
	timeout time.Duration
}

func (checker expressionSyntaxChecker) check(frame string) error {
	unavailable := func() error { return fmt.Errorf("%w: syntax check unavailable", ErrCSPExpression) }
	file, err := os.CreateTemp("", "mac-browser-expression-*.js") // CreateTemp uses 0600.
	if err != nil {
		return unavailable()
	}
	defer os.Remove(file.Name())
	_, writeErr := file.WriteString(frame)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return unavailable()
	}
	// checkSyntax alone accepts balanced escapes that close the intended function
	// and open a replacement. Also compile the intended body as a Function body:
	// its implicit braces cannot be closed by caller text. NEVER call that function.
	// This local parser process runs no caller code; the page wrapper has no Function.
	prefix, _ := json.Marshal(expressionFramePrefix)
	suffix, _ := json.Marshal(expressionFrameSuffix)
	program := fmt.Sprintf(`try {
  const frame = readFile(arguments[0]);
  checkSyntax(arguments[0]);
  new Function(frame.slice(%s.length, -%s.length));
  print("confined");
} catch (error) {
  if (error instanceof SyntaxError) print("invalid");
  else quit(1);
}`, prefix, suffix)
	ctx, cancel := context.WithTimeout(context.Background(), checker.timeout)
	defer cancel()
	// No shell, no caller text in argv, and no engine diagnostics/source in errors.
	out, err := exec.CommandContext(ctx, checker.path, "-e", program, "--", file.Name()).Output()
	if err != nil || ctx.Err() != nil {
		return unavailable()
	}
	switch strings.TrimSpace(string(out)) {
	case "confined":
		return nil
	case "invalid":
		return fmt.Errorf("%w: source is not confined to one expression", ErrCSPExpression)
	default:
		return unavailable()
	}
}
