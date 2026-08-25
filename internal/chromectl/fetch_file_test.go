package chromectl

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/mac-infra/internal/browsersession"
)

func TestNormalizeFetchFileRequestRejectsUnsafeAndUnboundedInputs(t *testing.T) {
	base := FetchFileRequest{ResourceURL: "/case/document", MaxBytes: 1024, Timeout: time.Second}
	for name, mutate := range map[string]func(*FetchFileRequest, *string){
		"http-origin":  func(request *FetchFileRequest, origin *string) { *origin = "http://example.com" },
		"origin-path":  func(request *FetchFileRequest, origin *string) { *origin = "https://example.com/path" },
		"cross-origin": func(request *FetchFileRequest, _ *string) { request.ResourceURL = "https://other.example/document" },
		"parent-domain": func(request *FetchFileRequest, origin *string) {
			*origin = "https://mail.example.com"
			request.ResourceURL = "https://example.com/document"
		},
		"sibling-subdomain": func(request *FetchFileRequest, origin *string) {
			*origin = "https://mail.example.com"
			request.ResourceURL = "https://files.example.com/document"
		},
		"suffix-host": func(request *FetchFileRequest, _ *string) { request.ResourceURL = "https://com/document" },
		"host-substring": func(request *FetchFileRequest, _ *string) {
			request.ResourceURL = "https://notexample.com/document"
		},
		"port-drift": func(request *FetchFileRequest, _ *string) { request.ResourceURL = "https://example.com:8443/document" },
		"host-case-drift": func(request *FetchFileRequest, _ *string) {
			request.ResourceURL = "https://EXAMPLE.com/document"
		},
		"scheme-relative-cross-origin": func(request *FetchFileRequest, _ *string) { request.ResourceURL = "//other.example/document" },
		"scheme-relative-same-origin":  func(request *FetchFileRequest, _ *string) { request.ResourceURL = "//example.com/document" },
		"credentials": func(request *FetchFileRequest, _ *string) {
			request.ResourceURL = "https://user:pass@example.com/document"
		},
		"fragment":          func(request *FetchFileRequest, _ *string) { request.ResourceURL = "/document#token" },
		"javascript-scheme": func(request *FetchFileRequest, _ *string) { request.ResourceURL = "javascript:alert(1)" },
		"zero-limit":        func(request *FetchFileRequest, _ *string) { request.MaxBytes = -1 },
		"oversized-limit":   func(request *FetchFileRequest, _ *string) { request.MaxBytes = MaximumFetchFileMaxBytes + 1 },
		"short-timeout":     func(request *FetchFileRequest, _ *string) { request.Timeout = time.Millisecond },
		"long-timeout":      func(request *FetchFileRequest, _ *string) { request.Timeout = MaximumFetchFileTimeout + time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			request := base
			origin := "https://example.com"
			mutate(&request, &origin)
			if _, _, err := normalizeFetchFileRequest(origin, request); err == nil {
				t.Fatal("unsafe or unbounded request was admitted")
			}
		})
	}
}

func TestFetchFileRejectsNonExactChromeIDsBeforeExecution(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	t.Setenv("MARKER", marker)
	session := Session{OsaScriptPath: writeFetchOsaScript(t, `touch "$MARKER"; exit 99`)}
	for _, ids := range [][2]string{{"", "2"}, {"01", "2"}, {"-1", "2"}, {"1", "tab"}} {
		_, _, err := session.FetchFile(context.Background(), ids[0], ids[1], "https://example.com", FetchFileRequest{ResourceURL: "/document", MaxBytes: 16, Timeout: time.Second})
		if err == nil {
			t.Fatalf("non-exact ids %#v were admitted", ids)
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("non-exact IDs reached browser execution: %v", err)
	}
}

func TestFetchFilePrivateProductionPathSupportsSequentialDownloadsAndKeepsResourceOutOfArgv(t *testing.T) {
	dir := t.TempDir()
	argvPath := filepath.Join(dir, "argv")
	statePath := filepath.Join(dir, "state")
	t.Setenv("ARGV_PATH", argvPath)
	t.Setenv("STATE_PATH", statePath)
	osa := writeFetchOsaScript(t, `
source=$(cat)
printf '%s\n' "$*" >> "$ARGV_PATH"
case "$source" in *https://example.com*) ;; *) printf 'origin guard missing\n' >&2; exit 98 ;; esac
case "$source" in
  *first-fake-download-token*) printf 'one' > "$STATE_PATH"; value='started' ;;
  *second-fake-download-token*) printf 'two' > "$STATE_PATH"; value='started' ;;
  *contentType:String*)
    state=$(cat "$STATE_PATH")
    value="{\"state\":\"done\",\"status\":200,\"bytes\":3,\"chunkCount\":1,\"contentType\":\"application/pdf; fake=drop\"}"
    ;;
  *job.chunks*)
    state=$(cat "$STATE_PATH")
    if [ "$state" = one ]; then value='{"state":"chunk","index":0,"data":"b25l"}'; else value='{"state":"chunk","index":0,"data":"dHdv"}'; fi
    ;;
  *different-job*) value='cleared' ;;
  *) value='unknown' ;;
esac
emit_value "$value"
`)
	session := Session{OsaScriptPath: osa}
	for _, tc := range []struct {
		resource string
		want     string
	}{
		{resource: "/first?token=first-fake-download-token", want: "one"},
		{resource: "https://example.com/second?signature=second-fake-download-token", want: "two"},
	} {
		data, meta, err := session.FetchFile(context.Background(), "11", "22", "https://example.com", FetchFileRequest{ResourceURL: tc.resource, MaxBytes: 16, Timeout: 60 * time.Second, PollEvery: time.Millisecond})
		if err != nil {
			argv, _ := os.ReadFile(argvPath)
			state, _ := os.ReadFile(statePath)
			t.Fatalf("FetchFile(%s): %v argv=%q state=%q", tc.want, err, argv, state)
		}
		if string(data) != tc.want || meta.Bytes != 3 || meta.Status != 200 || meta.ContentType != "application/pdf" {
			t.Fatalf("FetchFile(%s) data=%q meta=%+v", tc.want, data, meta)
		}
	}
	argv, err := os.ReadFile(argvPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"first-fake-download-token", "second-fake-download-token", "example.com/first", "example.com/second"} {
		if strings.Contains(string(argv), forbidden) {
			t.Fatalf("private FetchFile production path exposed resource in osascript argv: %q", argv)
		}
	}
}

func TestFetchFileFailsClosedOnOriginDriftAndTargetLoss(t *testing.T) {
	for name, body := range map[string]string{
		"origin-drift": `cat >/dev/null; emit_guard '{"__macBrowserSessionGuard":"works.relux.mac-infra/browser-session-guard/v1","outcome":"origin-mismatch","origin":"https://drift.example"}'`,
		"target-loss":  `cat >/dev/null; seal_outcome tab-missing`,
	} {
		t.Run(name, func(t *testing.T) {
			session := Session{OsaScriptPath: writeFetchOsaScript(t, body)}
			_, _, err := session.FetchFile(context.Background(), "11", "22", "https://example.com", FetchFileRequest{ResourceURL: "/document", MaxBytes: 16, Timeout: 60 * time.Second})
			if name == "origin-drift" && !errors.Is(err, browsersession.ErrOriginMismatch) {
				t.Fatalf("error=%v want origin mismatch", err)
			}
			if name == "target-loss" && !errors.Is(err, browsersession.ErrTargetMissing) {
				t.Fatalf("error=%v want target missing", err)
			}
		})
	}
}

func TestFetchFileFailsClosedOnPageAndDecodedSizeLimits(t *testing.T) {
	for name, pollValue := range map[string]string{
		"page-attested-over-limit": `{"state":"done","status":200,"bytes":4,"chunkCount":1}`,
		"page-size-refusal":        `{"state":"error","kind":"size-limit"}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("POLL_VALUE", pollValue)
			session := Session{OsaScriptPath: writeFetchOsaScript(t, `
source=$(cat)
case "$source" in
  *contentType:String*) value="$POLL_VALUE" ;;
  *different-job*) value='cleared' ;;
  *) value='started' ;;
esac
emit_value "$value"
`)}
			_, _, err := session.FetchFile(context.Background(), "11", "22", "https://example.com", FetchFileRequest{ResourceURL: "/document", MaxBytes: 3, Timeout: 60 * time.Second})
			if !errors.Is(err, ErrFetchSizeLimit) {
				t.Fatalf("error=%v want size limit", err)
			}
		})
	}
}

func TestFetchFileFailsClosedOnTimeout(t *testing.T) {
	session := Session{OsaScriptPath: writeFetchOsaScript(t, `
source=$(cat)
if printf '%s' "$source" | grep -q 'contentType:String'; then value='{"state":"running"}'; else value='started'; fi
emit_value "$value"
`)}
	_, _, err := session.FetchFile(context.Background(), "11", "22", "https://example.com", FetchFileRequest{ResourceURL: "/document", MaxBytes: 16, Timeout: 500 * time.Millisecond, PollEvery: time.Millisecond})
	if !errors.Is(err, ErrFetchTimeout) {
		t.Fatalf("error=%v want timeout", err)
	}
}

func TestStartFetchFileJavaScriptOwnsBrowserOnlyAuthAndHardBounds(t *testing.T) {
	source := startFetchFileJavaScript("0123456789abcdef", "https://example.com/document?token=fake", 1234, 2*time.Second, 512)
	for _, want := range []string{`credentials:"same-origin"`, `redirect:"error"`, `cache:"no-store"`, "total>maxBytes", "controller.abort()", "target.origin!==location.origin", "response.headers.get(\"content-type\")"} {
		if !strings.Contains(source, want) {
			t.Fatalf("sealed fetch source missing %q", want)
		}
	}
	for _, forbidden := range append(browsersession.BlockedJavaScriptTokens(), "authorization", "set-cookie", "content-disposition") {
		if strings.Contains(strings.ToLower(source), forbidden) {
			t.Fatalf("sealed fetch source contains forbidden secret surface %q", forbidden)
		}
	}
}

func writeFetchOsaScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "osascript")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+fakeOsaScriptPrelude+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDecodeFetchFileRequestAcceptsOnlyBoundedVersionedEnvelopes(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		request, err := DecodeFetchFileRequest(strings.NewReader(`{"version":1,"resource":"/report.pdf"}`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if request.ResourceURL != "/report.pdf" || request.MaxBytes != 0 || request.Timeout != 0 {
			t.Fatalf("decoded=%+v want resource only so normalizeFetchFileRequest applies the sealed defaults", request)
		}
		resolved, normalized, err := normalizeFetchFileRequest("https://example.com", request)
		if err != nil {
			t.Fatal(err)
		}
		if resolved != "https://example.com/report.pdf" || normalized.MaxBytes != DefaultFetchFileMaxBytes || normalized.Timeout != 90*time.Second {
			t.Fatalf("defaults were not applied: resolved=%q normalized=%+v", resolved, normalized)
		}
	})
	t.Run("explicit bounds", func(t *testing.T) {
		request, err := DecodeFetchFileRequest(strings.NewReader(`{"version":1,"resource":"/a.pdf","maxBytes":4096,"timeoutMs":1500}`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if request.MaxBytes != 4096 || request.Timeout != 1500*time.Millisecond {
			t.Fatalf("bounds were not carried: %+v", request)
		}
	})
	for name, body := range map[string]string{
		"empty":              "",
		"blank":              "  \n\t ",
		"not-json":           "/report.pdf",
		"missing version":    `{"resource":"/a.pdf"}`,
		"version zero":       `{"version":0,"resource":"/a.pdf"}`,
		"future version":     `{"version":2,"resource":"/a.pdf"}`,
		"unknown field":      `{"version":1,"resource":"/a.pdf","headers":{"cookie":"x"}}`,
		"trailing envelope":  `{"version":1,"resource":"/a.pdf"} {"version":1,"resource":"/b.pdf"}`,
		"oversized envelope": `{"version":1,"resource":"/` + strings.Repeat("a", MaxFetchFileRequestBytes) + `"}`,
		"oversized resource": `{"version":1,"resource":"` + strings.Repeat("b", maxFetchFileResourceBytes+1) + `"}`,
		"negative timeout":   `{"version":1,"resource":"/a.pdf","timeoutMs":-1}`,
		"timeout over max":   `{"version":1,"resource":"/a.pdf","timeoutMs":300001}`,
	} {
		t.Run(name, func(t *testing.T) {
			request, err := DecodeFetchFileRequest(strings.NewReader(body))
			if err == nil {
				t.Fatalf("envelope was accepted: %+v", request)
			}
			// A refusal must never echo the envelope back to a caller's stderr.
			if strings.Contains(err.Error(), "/a.pdf") || strings.Contains(err.Error(), strings.Repeat("a", 32)) || strings.Contains(err.Error(), strings.Repeat("b", 32)) {
				t.Fatalf("refusal echoed envelope content: %v", err)
			}
		})
	}
}

// TestDecodeFetchFileRequestBoundsTimeoutBeforeDurationConversion narrows the
// timeout bound instead of only probing its adjacent edge. time.Duration is
// int64 nanoseconds, so `time.Duration(timeoutMs) * time.Millisecond` wraps for
// large millisecond counts. Comparing after that multiplication admitted
// timeoutMs=288230376151711754 as a 10ms request even though the envelope
// contract refuses everything above 300000.
func TestDecodeFetchFileRequestBoundsTimeoutBeforeDurationConversion(t *testing.T) {
	if wrapped := time.Duration(overflowTimeoutMS) * time.Millisecond; wrapped > MaximumFetchFileTimeout || wrapped < 0 {
		t.Fatalf("overflow fixture no longer wraps on this platform: %s; the narrowing case would be vacuous", wrapped)
	}
	for name, timeoutMS := range map[string]int{
		"integer-overflow-wraps-into-range": overflowTimeoutMS,
		"platform-integer-maximum":          math.MaxInt,
		"one-over-maximum":                  int(MaximumFetchFileTimeout.Milliseconds()) + 1,
	} {
		t.Run(name, func(t *testing.T) {
			body := `{"version":1,"resource":"/report.pdf","timeoutMs":` + strconv.Itoa(timeoutMS) + `}`
			request, err := DecodeFetchFileRequest(strings.NewReader(body))
			if err == nil {
				t.Fatalf("out-of-range timeoutMs was admitted as %s", request.Timeout)
			}
			if strings.Contains(err.Error(), "/report.pdf") {
				t.Fatalf("refusal echoed envelope content: %v", err)
			}
		})
	}
	t.Run("exact-maximum-still-accepted", func(t *testing.T) {
		request, err := DecodeFetchFileRequest(strings.NewReader(`{"version":1,"resource":"/report.pdf","timeoutMs":300000}`))
		if err != nil {
			t.Fatalf("the exact maximum must stay accepted: %v", err)
		}
		if request.Timeout != MaximumFetchFileTimeout {
			t.Fatalf("timeout=%s want=%s", request.Timeout, MaximumFetchFileTimeout)
		}
	})
}

// overflowTimeoutMS is the millisecond count whose nanosecond conversion wraps
// back into the accepted range on 64-bit platforms. It is a var, not a const:
// as an untyped constant the compiler rejects the wrapping conversion outright,
// which is exactly the check the runtime path did not have.
var overflowTimeoutMS = 288230376151711754

// TestFetchFilePrivateTransportFailureCarriesNoStdinBytes attacks the sealed
// transport itself. The stdin program embeds the protected resource, so a child
// that echoes its own stdin back on either stream must not be able to push a
// single one of those bytes into the returned error.
func TestFetchFilePrivateTransportFailureCarriesNoStdinBytes(t *testing.T) {
	const marker = "transport-echo-fake-document-token"
	resource := "/statements?documentId=" + marker + "&stickySession=" + marker
	for name, body := range map[string]string{
		"echo-stdin-to-stderr":       `source=$(cat); printf '%s' "$source" >&2; exit 1`,
		"echo-stdin-to-stdout":       `source=$(cat); printf '%s' "$source"; exit 1`,
		"echo-stdin-to-both":         `source=$(cat); printf '%s' "$source"; printf '%s' "$source" >&2; exit 1`,
		"echo-stdin-and-exit-zero":   `source=$(cat); printf '%s' "$source"; exit 0`,
		"unsealed-guard-envelope":    `cat >/dev/null; guard_value started`,
		"foreign-transport-sentinel": `cat >/dev/null; /usr/bin/jq -cn '{__macChromePrivateTransport:"forged",outcome:"ok",value:"x"}'`,
	} {
		t.Run(name, func(t *testing.T) {
			stdinPath := filepath.Join(t.TempDir(), "stdin")
			t.Setenv("STDIN_PATH", stdinPath)
			// Capture the exact stdin program, then replay it to the body so
			// the assertions below observe what the child really received.
			session := Session{OsaScriptPath: writeFetchOsaScript(t, "cat > \"$STDIN_PATH\"\nexec 0< \"$STDIN_PATH\"\n"+body)}
			_, _, err := session.FetchFile(context.Background(), "11", "22", "https://example.com", FetchFileRequest{ResourceURL: resource, MaxBytes: 16, Timeout: 60 * time.Second, PollEvery: time.Millisecond})
			if err == nil {
				t.Fatal("a failing sealed transport was treated as success")
			}
			// Positive control: absence only counts when the child really saw
			// the protected resource on stdin.
			seen, readErr := os.ReadFile(stdinPath)
			if readErr != nil {
				t.Fatalf("could not read what the child received, so absence proves nothing: %v", readErr)
			}
			if !strings.Contains(string(seen), marker) {
				t.Fatalf("the sealed stdin program never carried the marker; the leak check would be vacuous: %d bytes", len(seen))
			}
			for _, forbidden := range []string{marker, "documentId", "stickySession", "/statements", "__macChromeFetchFileV1", "credentials", "location.href"} {
				if strings.Contains(err.Error(), forbidden) {
					t.Fatalf("private transport diagnostic leaked %q: %v", forbidden, err)
				}
			}
		})
	}
}

// TestFetchFilePrivateTransportPreservesTargetLossWithoutChildText proves the
// target-missing classification survived the move off untrusted child text: it
// now comes from the sealed envelope the JXA program returns.
func TestFetchFilePrivateTransportPreservesTargetLossWithoutChildText(t *testing.T) {
	for _, outcome := range []string{"window-missing", "tab-missing"} {
		t.Run(outcome, func(t *testing.T) {
			session := Session{OsaScriptPath: writeFetchOsaScript(t, `cat >/dev/null; seal_outcome `+outcome)}
			_, _, err := session.FetchFile(context.Background(), "11", "22", "https://example.com", FetchFileRequest{ResourceURL: "/document", MaxBytes: 16, Timeout: 60 * time.Second, PollEvery: time.Millisecond})
			if !errors.Is(err, browsersession.ErrTargetMissing) {
				t.Fatalf("error=%v want ErrTargetMissing", err)
			}
		})
	}
	t.Run("child-text-alone-is-not-target-loss", func(t *testing.T) {
		session := Session{OsaScriptPath: writeFetchOsaScript(t, `cat >/dev/null; printf '%s\n' 'Chrome target tab is no longer open' >&2; exit 1`)}
		_, _, err := session.FetchFile(context.Background(), "11", "22", "https://example.com", FetchFileRequest{ResourceURL: "/document", MaxBytes: 16, Timeout: 60 * time.Second, PollEvery: time.Millisecond})
		// The public boundary is sealed, so the lower-layer ErrPrivateTransport
		// sentinel is deliberately no longer reachable from outside. What must
		// survive is that a child claiming target loss in free text gets the
		// transport code and never the target-loss classification.
		if code := AsFetchFileDiagnostic(err).Code(); code != FetchFileTransportFailed {
			t.Fatalf("error=%v code=%d want FetchFileTransportFailed; a child must not be able to claim a classification through free text", err, code)
		}
		if errors.Is(err, browsersession.ErrTargetMissing) {
			t.Fatalf("child free text claimed target loss: %v", err)
		}
		if errors.Is(err, ErrPrivateTransport) {
			t.Fatalf("the lower-layer transport sentinel escaped the fetch-file seal: %v", err)
		}
	})
}

// TestPrivateTransportProgramDropsCaughtErrorDetail pins the page-context
// program shape: the catch arm must discard the caught error, because a JXA
// execute error can quote the evaluated program, and that program carries the
// protected resource reference.
func TestPrivateTransportProgramDropsCaughtErrorDetail(t *testing.T) {
	var captured string
	session := Session{OsaScriptPath: writeFetchOsaScript(t, `cat > "$PROGRAM_PATH"; exit 1`)}
	programPath := filepath.Join(t.TempDir(), "program")
	t.Setenv("PROGRAM_PATH", programPath)
	_, _ = session.runJavaScriptPrivate(context.Background(), "11", "22", "https://example.com", `"probe"`)
	data, err := os.ReadFile(programPath)
	if err != nil {
		t.Fatal(err)
	}
	captured = string(data)
	for _, want := range []string{`seal("window-missing")`, `seal("tab-missing")`, `catch(_)`, `seal("execute-failed")`, privateTransportSentinel} {
		if !strings.Contains(captured, want) {
			t.Fatalf("sealed program missing %q", want)
		}
	}
	for _, forbidden := range []string{"error.message", "String(error)", "e.message", "throw new Error"} {
		if strings.Contains(captured, forbidden) {
			t.Fatalf("sealed program can forward caught error detail via %q", forbidden)
		}
	}
}

// TestFetchFileSealedTransportDropsForgedNestedOriginValue narrows the forge
// past the fixed unreadable-response branch: the child mints a valid outer
// private-transport seal wrapping a *valid* nested browser-session guard
// envelope, so the nested value parses and reaches the origin classification.
// Both sentinels authenticate envelope shape, not provenance, and this child
// received the resource-bearing program, so its reported origin is untrusted.
func TestFetchFileSealedTransportDropsForgedNestedOriginValue(t *testing.T) {
	const marker = "nested-origin-forge-fake-document-token"
	resource := "/statements?documentId=" + marker + "&stickySession=" + marker
	for name, outcome := range map[string]string{
		"nested-origin-mismatch": "origin-mismatch",
		"nested-ok-origin-drift": "ok",
	} {
		t.Run(name, func(t *testing.T) {
			stdinPath := filepath.Join(t.TempDir(), "stdin")
			t.Setenv("STDIN_PATH", stdinPath)
			t.Setenv("FORGED_OUTCOME", outcome)
			session := Session{OsaScriptPath: writeFetchOsaScript(t, `cat > "$STDIN_PATH"
source=$(cat "$STDIN_PATH")
guard=$(/usr/bin/jq -cn --arg s "$__GUARD_SENTINEL" --arg out "$FORGED_OUTCOME" --arg org "$source" '{__macBrowserSessionGuard:$s,outcome:$out,origin:$org,readyState:"complete",value:""}')
emit_guard "$guard"`)}
			_, _, err := session.FetchFile(context.Background(), "11", "22", "https://example.com", FetchFileRequest{ResourceURL: resource, MaxBytes: 16, Timeout: 60 * time.Second, PollEvery: time.Millisecond})
			if err == nil {
				t.Fatal("a forged nested guard envelope was treated as success")
			}
			// Positive control: absence only counts once the child actually
			// received the resource-bearing program it could have echoed.
			seen, readErr := os.ReadFile(stdinPath)
			if readErr != nil {
				t.Fatalf("could not read what the child received, so absence proves nothing: %v", readErr)
			}
			if !strings.Contains(string(seen), marker) {
				t.Fatalf("the sealed stdin program never carried the marker; the leak check would be vacuous: %d bytes", len(seen))
			}
			for _, forbidden := range []string{marker, "documentId", "stickySession", "/statements", "__macChromeFetchFileV1", "credentials", "location.href", "__macBrowserSessionGuard"} {
				if strings.Contains(err.Error(), forbidden) {
					t.Fatalf("sealed transport leaked %q through a forged nested guard envelope: %v", forbidden, err)
				}
			}
			// The classification must survive, so a mutant that deletes the
			// branch outright cannot pass this test either.
			if !errors.Is(err, browsersession.ErrOriginMismatch) {
				t.Fatalf("origin-drift classification was lost: %v", err)
			}
			// No typed OriginMismatchError may escape this path at all: its
			// Observed field is exactly the child-controlled value.
			var mismatch *browsersession.OriginMismatchError
			if errors.As(err, &mismatch) {
				t.Fatalf("sealed transport returned a typed OriginMismatchError carrying child input: observed=%q", mismatch.Observed)
			}
		})
	}
}
