package main

import (
	"bytes"
	"testing"
)

// Usage errors and malformed baselines fail before collecting live evidence;
// help and version remain successful controls.
func TestCommandValidation(t *testing.T) {
	for _, row := range []struct {
		args []string
		code int
	}{{nil, 2}, {[]string{"scan", "--file", "x"}, 2}, {[]string{"baseline"}, 2}, {[]string{"diff", "--file", "/nonexistent/security-fixture"}, 1}, {[]string{"scan", "--ioc-file", "/nonexistent/security-fixture"}, 2}, {[]string{"help"}, 0}, {[]string{"version"}, 0}, {[]string{"nope"}, 2}} {
		var out, err bytes.Buffer
		if got := run(row.args, &out, &err); got != row.code {
			t.Fatalf("%v: %d %s", row.args, got, err.String())
		}
	}
}
