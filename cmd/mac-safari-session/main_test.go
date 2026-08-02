package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run code = %d, stderr = %s", code, stderr.String())
	}
	for _, want := range []string{"mac-safari-session", "open-bg", "close-window", "fetch-file"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestCloseWindowRequiresPositiveID(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"close-window"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run code = %d, want 2; stdout = %s stderr = %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "requires --id") {
		t.Fatalf("stderr missing required id message:\n%s", stderr.String())
	}
}

func TestRunJSRejectsCookieReadBeforeSafari(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"run-js", "--script", "document.cookie"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run code = %d, want 1; stdout = %s stderr = %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "do not export cookies") {
		t.Fatalf("stderr missing safety explanation:\n%s", stderr.String())
	}
}

func TestRunJSRejectsNegativeWindowIDBeforeSafari(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"run-js", "--window-id", "-1", "--script", "document.title"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run code = %d, want 2; stdout = %s stderr = %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "--window-id must be a positive") {
		t.Fatalf("stderr missing window id explanation:\n%s", stderr.String())
	}
}

func TestRunJSHelpDocumentsWindowID(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"run-js", "--help"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run code = %d, want 2; stdout = %s stderr = %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "--window-id") {
		t.Fatalf("stderr missing --window-id help:\n%s", stderr.String())
	}
}

func TestFetchFileRequiresResourceAndOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"fetch-file", "--resource", "/api/file"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run code = %d, want 2; stdout = %s stderr = %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "requires --resource and --out") {
		t.Fatalf("stderr missing required flags message:\n%s", stderr.String())
	}
}
