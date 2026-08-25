package chromectl

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/mac-infra/internal/browsersession"
)

// fetchFileFixedMessages is an independent transcription of the closed
// vocabulary. Assertions compare against these literals rather than against
// Message() itself: a self-referential comparison would pass for any mutant that
// changed the implementation and the expectation together.
var fetchFileFixedMessages = map[FetchFileDiagnosticCode]string{
	FetchFileUnverifiable:         "fetch-file failed safely",
	FetchFileUsage:                "fetch-file invocation was refused",
	FetchFileRequestUnreadable:    "fetch-file request could not be verified",
	FetchFileRequestRefused:       "fetch-file request was refused",
	FetchFileTargetMissing:        "browser target is no longer available",
	FetchFileOriginMismatch:       "browser target origin changed",
	FetchFileTransportUnavailable: "Chrome page-context transport is unavailable",
	FetchFileTransportFailed:      "Chrome page-context transport failed",
	FetchFileResponseUnverifiable: "Chrome page-context response could not be verified",
	FetchFileBusy:                 "another sealed fetch is already running",
	FetchFileSizeLimit:            "fetch response exceeded the configured size limit",
	FetchFileTimeout:              "fetch response exceeded the configured timeout",
	FetchFileHTTPStatus:           "authenticated fetch returned a non-success status",
	FetchFileRedirectRefused:      "authenticated fetch redirect was refused",
	FetchFilePageFailed:           "authenticated page-context fetch failed",
	FetchFileOutputPrepare:        "private output could not be prepared",
	FetchFileOutputWrite:          "private output could not be published",
}

// TestFetchFileDiagnosticMapsEveryCodeToFixedMessageAndExit pins the closed
// vocabulary. Every defined code must resolve to its own literal, and every
// value outside the set — including the numeric values just past the enum and a
// forged large code — must collapse to the safe unverifiable literal rather than
// being rendered.
func TestFetchFileDiagnosticMapsEveryCodeToFixedMessageAndExit(t *testing.T) {
	for name, tc := range map[string]struct {
		code    FetchFileDiagnosticCode
		message string
		exit    int
	}{
		"unverifiable":          {FetchFileUnverifiable, "fetch-file failed safely", 1},
		"usage":                 {FetchFileUsage, "fetch-file invocation was refused", 2},
		"request-unreadable":    {FetchFileRequestUnreadable, "fetch-file request could not be verified", 2},
		"request-refused":       {FetchFileRequestRefused, "fetch-file request was refused", 1},
		"target-missing":        {FetchFileTargetMissing, "browser target is no longer available", 1},
		"origin-mismatch":       {FetchFileOriginMismatch, "browser target origin changed", 1},
		"transport-unavailable": {FetchFileTransportUnavailable, "Chrome page-context transport is unavailable", 1},
		"transport-failed":      {FetchFileTransportFailed, "Chrome page-context transport failed", 1},
		"response-unverifiable": {FetchFileResponseUnverifiable, "Chrome page-context response could not be verified", 1},
		"busy":                  {FetchFileBusy, "another sealed fetch is already running", 1},
		"size-limit":            {FetchFileSizeLimit, "fetch response exceeded the configured size limit", 1},
		"timeout":               {FetchFileTimeout, "fetch response exceeded the configured timeout", 1},
		"http-status":           {FetchFileHTTPStatus, "authenticated fetch returned a non-success status", 1},
		"redirect-refused":      {FetchFileRedirectRefused, "authenticated fetch redirect was refused", 1},
		"page-failed":           {FetchFilePageFailed, "authenticated page-context fetch failed", 1},
		"output-prepare":        {FetchFileOutputPrepare, "private output could not be prepared", 1},
		"output-write":          {FetchFileOutputWrite, "private output could not be published", 1},
	} {
		t.Run(name, func(t *testing.T) {
			diagnostic := NewFetchFileDiagnostic(tc.code)
			if diagnostic.Code() != tc.code {
				t.Fatalf("code=%d want=%d", diagnostic.Code(), tc.code)
			}
			if fetchFileFixedMessages[tc.code] != tc.message {
				t.Fatalf("pinned literal drifted from the case table for code %d", tc.code)
			}
			if diagnostic.Message() != tc.message || diagnostic.Error() != tc.message {
				t.Fatalf("message=%q error=%q want=%q", diagnostic.Message(), diagnostic.Error(), tc.message)
			}
			if diagnostic.ExitCode() != tc.exit {
				t.Fatalf("exit=%d want=%d", diagnostic.ExitCode(), tc.exit)
			}
		})
	}
	// Unknown codes are the forged-evidence shape for this boundary: a numeric
	// value must never be rendered, and must never buy a quieter exit status.
	for name, code := range map[string]FetchFileDiagnosticCode{
		"one-past-the-enum": FetchFileOutputWrite + 1,
		"mid-range":         99,
		"max-uint8":         255,
	} {
		t.Run("unknown-"+name, func(t *testing.T) {
			diagnostic := NewFetchFileDiagnostic(code)
			if diagnostic.Code() != FetchFileUnverifiable {
				t.Fatalf("unknown code %d was retained as %d", code, diagnostic.Code())
			}
			if diagnostic.Message() != "fetch-file failed safely" || diagnostic.ExitCode() != 1 {
				t.Fatalf("unknown code %d rendered %q exit=%d", code, diagnostic.Message(), diagnostic.ExitCode())
			}
			if strings.ContainsAny(diagnostic.Message(), "0123456789") {
				t.Fatalf("unknown code leaked a numeric value: %q", diagnostic.Message())
			}
		})
	}
	// A zero-value diagnostic must also be safe: a struct that skipped the
	// constructor cannot become a formatting hole.
	if zero := (FetchFileDiagnostic{}); zero.Message() != "fetch-file failed safely" || zero.ExitCode() != 1 {
		t.Fatalf("zero-value diagnostic is not fail-closed: %q exit=%d", zero.Message(), zero.ExitCode())
	}
}

// TestFetchFileDiagnosticRetainsNoCauseOrDetail is the structural guard behind
// the whole boundary: the type must have exactly one unexported enum field. A
// detail, cause, path, origin, or wrapped error field is the mechanism by which
// every earlier revision leaked, so its absence is asserted, not assumed.
func TestFetchFileDiagnosticRetainsNoCauseOrDetail(t *testing.T) {
	typ := reflect.TypeOf(FetchFileDiagnostic{})
	if typ.Kind() != reflect.Struct || typ.NumField() != 1 {
		t.Fatalf("FetchFileDiagnostic has %d fields; exactly one closed enum field is allowed", typ.NumField())
	}
	field := typ.Field(0)
	if field.IsExported() {
		t.Fatalf("field %q is exported; a caller could set arbitrary detail", field.Name)
	}
	if field.Type != reflect.TypeOf(FetchFileDiagnosticCode(0)) {
		t.Fatalf("field %q has type %s; only the closed code type is allowed", field.Name, field.Type)
	}
	if kind := field.Type.Kind(); kind != reflect.Uint8 {
		t.Fatalf("code type kind=%s; a string or interface kind could carry untrusted bytes", kind)
	}
	// No method may reach an error: without Unwrap there is nothing to retain.
	if _, ok := any(FetchFileDiagnostic{}).(interface{ Unwrap() error }); ok {
		t.Fatal("FetchFileDiagnostic implements Unwrap; a retained cause can be formatted by any caller")
	}
}

// TestFetchFileDiagnosticPreservesClassificationWithoutTypedLowerLayerErrors
// proves the required errors.Is classification survived while the detail-bearing
// lower-layer types did not.
func TestFetchFileDiagnosticPreservesClassificationWithoutTypedLowerLayerErrors(t *testing.T) {
	targetMissing := error(NewFetchFileDiagnostic(FetchFileTargetMissing))
	originMismatch := error(NewFetchFileDiagnostic(FetchFileOriginMismatch))
	if !errors.Is(targetMissing, browsersession.ErrTargetMissing) {
		t.Fatal("target-missing lost its ErrTargetMissing classification")
	}
	if !errors.Is(originMismatch, browsersession.ErrOriginMismatch) {
		t.Fatal("origin-mismatch lost its ErrOriginMismatch classification")
	}
	// Narrowing: the classification must be exact, not a blanket true.
	if errors.Is(targetMissing, browsersession.ErrOriginMismatch) || errors.Is(originMismatch, browsersession.ErrTargetMissing) {
		t.Fatal("classification is not exclusive; Is answers true for the wrong sentinel")
	}
	if errors.Is(NewFetchFileDiagnostic(FetchFileTransportFailed), browsersession.ErrTargetMissing) {
		t.Fatal("an unrelated code claimed target loss")
	}
	var mismatch *browsersession.OriginMismatchError
	if errors.As(originMismatch, &mismatch) {
		t.Fatalf("a typed OriginMismatchError escaped: observed=%q", mismatch.Observed)
	}
	var missing *browsersession.TargetMissingError
	if errors.As(targetMissing, &missing) {
		t.Fatalf("a typed TargetMissingError escaped: detail=%q", missing.Detail)
	}
	for code, sentinel := range map[FetchFileDiagnosticCode]error{
		FetchFileSizeLimit:      ErrFetchSizeLimit,
		FetchFileTimeout:        ErrFetchTimeout,
		FetchFileBusy:           ErrFetchBusy,
		FetchFileRequestRefused: ErrUnsafeFetchURL,
	} {
		if !errors.Is(NewFetchFileDiagnostic(code), sentinel) {
			t.Fatalf("code %d lost its %v classification", code, sentinel)
		}
	}
}

// TestAsFetchFileDiagnosticCollapsesUnsealedErrors covers the CLI's extraction
// point. An error that is not already sealed — the shape a missed conversion or
// a future bypass would produce — must collapse to the safe code instead of
// being rendered.
func TestAsFetchFileDiagnosticCollapsesUnsealedErrors(t *testing.T) {
	const marker = "as-diagnostic-fake-document-token"
	for name, err := range map[string]error{
		"nil":                nil,
		"plain":              errors.New("lstat /tmp/" + marker + "/out.bin: not a directory"),
		"wrapped-sentinel":   fmt.Errorf("%w: origin was %s", browsersession.ErrOriginMismatch, marker),
		"typed-lower-layer":  &browsersession.OriginMismatchError{Expected: "https://example.com", Observed: marker},
		"typed-target-lost":  &browsersession.TargetMissingError{Browser: browsersession.BrowserChrome, Target: marker, Detail: marker},
		"private-transport":  &PrivateTransportError{Kind: marker},
		"double-wrapped-fmt": fmt.Errorf("prepare output: %w", fmt.Errorf("inspect path: %s", marker)),
	} {
		t.Run(name, func(t *testing.T) {
			diagnostic := AsFetchFileDiagnostic(err)
			if diagnostic.Code() != FetchFileUnverifiable {
				t.Fatalf("unsealed error was classified as %d instead of collapsing", diagnostic.Code())
			}
			if strings.Contains(diagnostic.Message(), marker) {
				t.Fatalf("extraction rendered untrusted detail: %q", diagnostic.Message())
			}
		})
	}
	// Positive control: a sealed diagnostic keeps its own code, so the collapse
	// above is a fail-closed default and not a blanket erasure.
	if code := AsFetchFileDiagnostic(NewFetchFileDiagnostic(FetchFileOutputWrite)).Code(); code != FetchFileOutputWrite {
		t.Fatalf("a sealed diagnostic was erased: code=%d", code)
	}
}

// TestFetchFileSealsEveryPublicErrorSeam drives the real public
// Session.FetchFile boundary against a marked failure at each internal seam.
// Every one must come back as the closed diagnostic with its fixed code and no
// marker: this is the narrowing evidence that the seal covers poll and chunk
// seams, not only the start call.
func TestFetchFileSealsEveryPublicErrorSeam(t *testing.T) {
	const marker = "seam-fake-document-token"
	resource := "/statements?documentId=" + marker + "&stickySession=" + marker
	for name, tc := range map[string]struct {
		body string
		want FetchFileDiagnosticCode
	}{
		"start-transport-failure": {
			body: `source=$(cat); printf '%s' "$source" >&2; exit 1`,
			want: FetchFileTransportFailed,
		},
		"start-unverifiable-value": {
			body: `cat >/dev/null; emit_value "` + marker + `"`,
			want: FetchFileResponseUnverifiable,
		},
		"start-busy": {
			body: `cat >/dev/null; emit_value busy`,
			want: FetchFileBusy,
		},
		"poll-transport-failure": {
			body: `source=$(cat); if printf '%s' "$source" | grep -q 'contentType:String'; then printf '%s' "$source" >&2; exit 1; fi; emit_value started`,
			want: FetchFileTransportFailed,
		},
		"poll-malformed-metadata": {
			body: `source=$(cat); if printf '%s' "$source" | grep -q 'contentType:String'; then emit_value '{"state":"done","surprise":"` + marker + `"}'; else emit_value started; fi`,
			want: FetchFileResponseUnverifiable,
		},
		"poll-unknown-state": {
			body: `source=$(cat); if printf '%s' "$source" | grep -q 'contentType:String'; then emit_value '{"state":"` + marker + `"}'; else emit_value started; fi`,
			want: FetchFileResponseUnverifiable,
		},
		"poll-missing-state": {
			body: `source=$(cat); if printf '%s' "$source" | grep -q 'contentType:String'; then emit_value '{"state":"missing"}'; else emit_value started; fi`,
			want: FetchFileResponseUnverifiable,
		},
		"page-http-status": {
			body: `source=$(cat); if printf '%s' "$source" | grep -q 'contentType:String'; then emit_value '{"state":"error","kind":"http-status","status":403}'; else emit_value started; fi`,
			want: FetchFileHTTPStatus,
		},
		"page-redirect-refused": {
			body: `source=$(cat); if printf '%s' "$source" | grep -q 'contentType:String'; then emit_value '{"state":"error","kind":"redirect-refused"}'; else emit_value started; fi`,
			want: FetchFileRedirectRefused,
		},
		"page-unknown-kind": {
			body: `source=$(cat); if printf '%s' "$source" | grep -q 'contentType:String'; then emit_value '{"state":"error","kind":"` + marker + `"}'; else emit_value started; fi`,
			want: FetchFilePageFailed,
		},
		"page-size-limit": {
			body: `source=$(cat); if printf '%s' "$source" | grep -q 'contentType:String'; then emit_value '{"state":"error","kind":"size-limit"}'; else emit_value started; fi`,
			want: FetchFileSizeLimit,
		},
		"page-timeout": {
			body: `source=$(cat); if printf '%s' "$source" | grep -q 'contentType:String'; then emit_value '{"state":"error","kind":"timeout"}'; else emit_value started; fi`,
			want: FetchFileTimeout,
		},
		"attested-bytes-over-limit": {
			body: `source=$(cat); if printf '%s' "$source" | grep -q 'contentType:String'; then emit_value '{"state":"done","status":200,"bytes":9999,"chunkCount":1}'; else emit_value started; fi`,
			want: FetchFileSizeLimit,
		},
		"attested-chunk-count-absurd": {
			body: `source=$(cat); if printf '%s' "$source" | grep -q 'contentType:String'; then emit_value '{"state":"done","status":200,"bytes":3,"chunkCount":99999}'; else emit_value started; fi`,
			want: FetchFileResponseUnverifiable,
		},
		"chunk-transport-failure": {
			body: `source=$(cat)
if printf '%s' "$source" | grep -q 'job.chunks'; then printf '%s' "$source" >&2; exit 1; fi
if printf '%s' "$source" | grep -q 'contentType:String'; then emit_value '{"state":"done","status":200,"bytes":3,"chunkCount":1}'; else emit_value started; fi`,
			want: FetchFileTransportFailed,
		},
		"chunk-index-drift": {
			body: `source=$(cat)
if printf '%s' "$source" | grep -q 'job.chunks'; then emit_value '{"state":"chunk","index":7,"data":"b25l"}'; exit 0; fi
if printf '%s' "$source" | grep -q 'contentType:String'; then emit_value '{"state":"done","status":200,"bytes":3,"chunkCount":1}'; else emit_value started; fi`,
			want: FetchFileResponseUnverifiable,
		},
		"chunk-undecodable-base64": {
			body: `source=$(cat)
if printf '%s' "$source" | grep -q 'job.chunks'; then emit_value '{"state":"chunk","index":0,"data":"` + marker + `!!"}'; exit 0; fi
if printf '%s' "$source" | grep -q 'contentType:String'; then emit_value '{"state":"done","status":200,"bytes":3,"chunkCount":1}'; else emit_value started; fi`,
			want: FetchFileResponseUnverifiable,
		},
		"chunk-byte-count-drift": {
			body: `source=$(cat)
if printf '%s' "$source" | grep -q 'job.chunks'; then emit_value '{"state":"chunk","index":0,"data":"b25l"}'; exit 0; fi
if printf '%s' "$source" | grep -q 'contentType:String'; then emit_value '{"state":"done","status":200,"bytes":2,"chunkCount":1}'; else emit_value started; fi`,
			want: FetchFileResponseUnverifiable,
		},
		"unsealed-outer-envelope": {
			body: `cat >/dev/null; printf '%s' '` + marker + `'`,
			want: FetchFileResponseUnverifiable,
		},
		"forged-outer-outcome": {
			body: `cat >/dev/null; seal_outcome '` + marker + `'`,
			want: FetchFileResponseUnverifiable,
		},
		"child-unavailable": {
			body: `cat >/dev/null; exit 0`,
			want: FetchFileResponseUnverifiable,
		},
		"target-loss": {
			body: `cat >/dev/null; seal_outcome window-missing`,
			want: FetchFileTargetMissing,
		},
		"execute-failed": {
			body: `cat >/dev/null; seal_outcome execute-failed`,
			want: FetchFileTransportFailed,
		},
	} {
		t.Run(name, func(t *testing.T) {
			session := Session{OsaScriptPath: writeFetchOsaScript(t, tc.body)}
			data, meta, err := session.FetchFile(context.Background(), "11", "22", "https://example.com", FetchFileRequest{ResourceURL: resource, MaxBytes: 3, Timeout: 30 * time.Second, PollEvery: time.Millisecond})
			if err == nil {
				t.Fatalf("seam %q was treated as success", name)
			}
			if data != nil || meta != (FetchFileMeta{}) {
				t.Fatalf("a failing seam returned payload/metadata: data=%q meta=%+v", data, meta)
			}
			assertSealedFetchFileError(t, err, tc.want, marker)
		})
	}
}

// TestFetchFileSealsIdentifierAndValidationSeams covers the two seams a fake
// osascript cannot reach: the sealed identifier's entropy source and the
// pre-flight validation branches that run before any browser contact.
func TestFetchFileSealsIdentifierAndValidationSeams(t *testing.T) {
	const marker = "identifier-fake-document-token"
	t.Run("random-identifier-failure", func(t *testing.T) {
		previous := fetchFileRandRead
		fetchFileRandRead = func(b []byte) (int, error) {
			return 0, errors.New("entropy source unavailable: " + marker)
		}
		defer func() { fetchFileRandRead = previous }()
		session := Session{OsaScriptPath: writeFetchOsaScript(t, `cat >/dev/null; emit_value started`)}
		_, _, err := session.FetchFile(context.Background(), "11", "22", "https://example.com", FetchFileRequest{ResourceURL: "/document?documentId=" + marker, MaxBytes: 16, Timeout: 30 * time.Second, PollEvery: time.Millisecond})
		assertSealedFetchFileError(t, err, FetchFileUnverifiable, marker)
	})
	for name, tc := range map[string]struct {
		windowID string
		tabID    string
		origin   string
		request  FetchFileRequest
	}{
		"cross-origin-resource": {"11", "22", "https://example.com", FetchFileRequest{ResourceURL: "https://other.example/x?documentId=" + marker, MaxBytes: 16, Timeout: time.Second}},
		"non-exact-window":      {"01", "22", "https://example.com", FetchFileRequest{ResourceURL: "/x?documentId=" + marker, MaxBytes: 16, Timeout: time.Second}},
		"non-exact-tab":         {"11", "tab-" + marker, "https://example.com", FetchFileRequest{ResourceURL: "/x", MaxBytes: 16, Timeout: time.Second}},
		"origin-with-path":      {"11", "22", "https://example.com/path", FetchFileRequest{ResourceURL: "/x?documentId=" + marker, MaxBytes: 16, Timeout: time.Second}},
		"oversized-limit":       {"11", "22", "https://example.com", FetchFileRequest{ResourceURL: "/x?documentId=" + marker, MaxBytes: MaximumFetchFileMaxBytes + 1, Timeout: time.Second}},
		"long-timeout":          {"11", "22", "https://example.com", FetchFileRequest{ResourceURL: "/x?documentId=" + marker, MaxBytes: 16, Timeout: MaximumFetchFileTimeout + time.Second}},
	} {
		t.Run(name, func(t *testing.T) {
			session := Session{OsaScriptPath: writeFetchOsaScript(t, `cat >/dev/null; exit 99`)}
			_, _, err := session.FetchFile(context.Background(), tc.windowID, tc.tabID, tc.origin, tc.request)
			assertSealedFetchFileError(t, err, FetchFileRequestRefused, marker)
		})
	}
}

// assertSealedFetchFileError is the shared invariant check: the public error is
// the closed concrete type, carries the expected fixed code, renders only its
// own literal, and exposes no lower-layer cause an errors.As caller could mine
// for detail.
func assertSealedFetchFileError(t *testing.T, err error, want FetchFileDiagnosticCode, marker string) {
	t.Helper()
	if err == nil {
		t.Fatal("a failing seam returned no error")
	}
	diagnostic, ok := err.(FetchFileDiagnostic)
	if !ok {
		t.Fatalf("public error is %T, not the sealed diagnostic: %v", err, err)
	}
	if diagnostic.Code() != want {
		t.Fatalf("code=%d want=%d (message=%q)", diagnostic.Code(), want, diagnostic.Message())
	}
	fixed, ok := fetchFileFixedMessages[want]
	if !ok {
		t.Fatalf("code %d has no pinned literal", want)
	}
	if err.Error() != fixed {
		t.Fatalf("message=%q is not the pinned literal %q for code %d", err.Error(), fixed, want)
	}
	if marker != "" && strings.Contains(err.Error(), marker) {
		t.Fatalf("public error leaked the marker: %q", err.Error())
	}
	for _, forbidden := range []string{"documentId", "stickySession", "/statements", "__macChromeFetchFileV1", "__macBrowserSessionGuard", "credentials", "location.href", "osascript"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("public error leaked %q: %q", forbidden, err.Error())
		}
	}
	var mismatch *browsersession.OriginMismatchError
	if errors.As(err, &mismatch) {
		t.Fatalf("a typed OriginMismatchError escaped the seal: observed=%q", mismatch.Observed)
	}
	var missing *browsersession.TargetMissingError
	if errors.As(err, &missing) {
		t.Fatalf("a typed TargetMissingError escaped the seal: detail=%q", missing.Detail)
	}
	var transport *PrivateTransportError
	if errors.As(err, &transport) {
		t.Fatalf("a PrivateTransportError escaped the seal: kind=%q", transport.Kind)
	}
}

// TestPrivateTransportDropsTypedOriginMismatchAtItsOwnBoundary pins the shared
// sealed transport directly, not through Session.FetchFile. The fetch-file seal
// would mask a regression here, but runJavaScriptPrivate is also the transport
// for trusted-input and upload, which have no such seal: a typed
// OriginMismatchError carrying the child's observed value must not be created at
// this layer in the first place.
func TestPrivateTransportDropsTypedOriginMismatchAtItsOwnBoundary(t *testing.T) {
	const marker = "shared-transport-forge-fake-document-token"
	for name, outcome := range map[string]string{
		"nested-origin-mismatch": "origin-mismatch",
		"nested-ok-origin-drift": "ok",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("FORGED_OUTCOME", outcome)
			session := Session{OsaScriptPath: writeFetchOsaScript(t, `cat >/dev/null
guard=$(/usr/bin/jq -cn --arg s "$__GUARD_SENTINEL" --arg out "$FORGED_OUTCOME" --arg org "`+marker+`" '{__macBrowserSessionGuard:$s,outcome:$out,origin:$org,readyState:"complete",value:""}')
emit_guard "$guard"`)}
			_, err := session.runJavaScriptPrivate(context.Background(), "11", "22", "https://example.com", `"probe"`)
			if err == nil {
				t.Fatal("a forged nested guard envelope was accepted by the shared transport")
			}
			if !errors.Is(err, browsersession.ErrOriginMismatch) {
				t.Fatalf("the shared transport lost the origin-drift classification: %v", err)
			}
			var mismatch *browsersession.OriginMismatchError
			if errors.As(err, &mismatch) {
				t.Fatalf("the shared transport returned a typed OriginMismatchError carrying child input: observed=%q", mismatch.Observed)
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("the shared transport rendered the child-controlled origin: %q", err.Error())
			}
		})
	}
}
