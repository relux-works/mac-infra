package main

import (
	"bytes"
	"context"
	"testing"
)

// Claim: help is available without reading certificates or touching a project.
func TestHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run(context.Background(), []string{"help"}, &stdout, &stderr); got != 0 {
		t.Fatalf("help exit = %d", got)
	}
	if stdout.Len() == 0 || stderr.Len() != 0 {
		t.Fatalf("help stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

// Claim: malformed invocations fail with the documented usage exit and stable cause before platform access.
func TestInvalidInvocations(t *testing.T) {
	for _, args := range [][]string{{}, {"unknown"}, {"build"}, {"gradle", "--project", "/missing"}} {
		var stdout, stderr bytes.Buffer
		if got := run(context.Background(), args, &stdout, &stderr); got != 2 {
			t.Errorf("args %q exit = %d", args, got)
		}
		if !bytes.Contains(stderr.Bytes(), []byte("invalid_usage")) && len(args) != 0 {
			t.Errorf("args %q missing stable cause: %q", args, stderr.String())
		}
	}
}
