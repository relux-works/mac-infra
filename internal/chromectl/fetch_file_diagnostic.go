package chromectl

import (
	"context"
	"errors"

	"github.com/relux-works/mac-infra/internal/browsersession"
)

// FetchFileDiagnosticCode is the closed vocabulary of every fetch-file failure.
//
// The fetch-file path carries a protected resource reference into a page
// context, so its outward error surface is deliberately less detailed than the
// layers beneath it. Three independent reviews found the same defect class at
// three different surfaces (argv, forwarded child streams, a self-minted nested
// origin value) because each surface owned its own formatting decision. This
// enum is the single owner: a code selects a literal, and nothing else can.
type FetchFileDiagnosticCode uint8

// The zero value is deliberately the safest code: a diagnostic constructed from
// an unset, unknown, or partially initialized value fails closed rather than
// describing anything.
const (
	FetchFileUnverifiable FetchFileDiagnosticCode = iota
	FetchFileUsage
	FetchFileRequestUnreadable
	FetchFileRequestRefused
	FetchFileTargetMissing
	FetchFileOriginMismatch
	FetchFileTransportUnavailable
	FetchFileTransportFailed
	FetchFileResponseUnverifiable
	FetchFileBusy
	FetchFileSizeLimit
	FetchFileTimeout
	FetchFileHTTPStatus
	FetchFileRedirectRefused
	FetchFilePageFailed
	FetchFileOutputPrepare
	FetchFileOutputWrite
)

// FetchFileDiagnostic is the only error type that may leave the fetch-file
// boundary. It has exactly one private enum field on purpose: with no error,
// string, path, origin, URL, page, request, stdout, or stderr member there is
// no place for an untrusted byte to hide, and no rendering path can be added by
// accident.
type FetchFileDiagnostic struct {
	code FetchFileDiagnosticCode
}

// NewFetchFileDiagnostic builds a diagnostic from a defined code. Any code
// outside the closed set collapses to FetchFileUnverifiable so an unmapped or
// forged numeric value can never reach a formatter.
func NewFetchFileDiagnostic(code FetchFileDiagnosticCode) FetchFileDiagnostic {
	switch code {
	case FetchFileUnverifiable,
		FetchFileUsage,
		FetchFileRequestUnreadable,
		FetchFileRequestRefused,
		FetchFileTargetMissing,
		FetchFileOriginMismatch,
		FetchFileTransportUnavailable,
		FetchFileTransportFailed,
		FetchFileResponseUnverifiable,
		FetchFileBusy,
		FetchFileSizeLimit,
		FetchFileTimeout,
		FetchFileHTTPStatus,
		FetchFileRedirectRefused,
		FetchFilePageFailed,
		FetchFileOutputPrepare,
		FetchFileOutputWrite:
		return FetchFileDiagnostic{code: code}
	default:
		return FetchFileDiagnostic{code: FetchFileUnverifiable}
	}
}

// Code reports the fixed classification. It is the only value a caller may read.
func (d FetchFileDiagnostic) Code() FetchFileDiagnosticCode { return d.code }

// Message is a total switch over the closed enum returning literals only. There
// is no default branch that formats the numeric code or any input value.
func (d FetchFileDiagnostic) Message() string {
	switch d.code {
	case FetchFileUsage:
		return "fetch-file invocation was refused"
	case FetchFileRequestUnreadable:
		return "fetch-file request could not be verified"
	case FetchFileRequestRefused:
		return "fetch-file request was refused"
	case FetchFileTargetMissing:
		return "browser target is no longer available"
	case FetchFileOriginMismatch:
		return "browser target origin changed"
	case FetchFileTransportUnavailable:
		return "Chrome page-context transport is unavailable"
	case FetchFileTransportFailed:
		return "Chrome page-context transport failed"
	case FetchFileResponseUnverifiable:
		return "Chrome page-context response could not be verified"
	case FetchFileBusy:
		return "another sealed fetch is already running"
	case FetchFileSizeLimit:
		return "fetch response exceeded the configured size limit"
	case FetchFileTimeout:
		return "fetch response exceeded the configured timeout"
	case FetchFileHTTPStatus:
		return "authenticated fetch returned a non-success status"
	case FetchFileRedirectRefused:
		return "authenticated fetch redirect was refused"
	case FetchFilePageFailed:
		return "authenticated page-context fetch failed"
	case FetchFileOutputPrepare:
		return "private output could not be prepared"
	case FetchFileOutputWrite:
		return "private output could not be published"
	default:
		return "fetch-file failed safely"
	}
}

// ExitCode is the fixed process status for the code. Invocation and request
// verification failures are usage errors; everything else is a run failure.
func (d FetchFileDiagnostic) ExitCode() int {
	switch d.code {
	case FetchFileUsage, FetchFileRequestUnreadable:
		return 2
	default:
		return 1
	}
}

func (d FetchFileDiagnostic) Error() string { return d.Message() }

// Is preserves the classifications callers legitimately switch on without
// retaining the lower-layer error that produced them. There is deliberately no
// Unwrap: a retained cause is exactly how observed origins, child text, and
// filesystem paths escaped in the earlier revisions.
func (d FetchFileDiagnostic) Is(target error) bool {
	switch d.code {
	case FetchFileTargetMissing:
		return target == browsersession.ErrTargetMissing
	case FetchFileOriginMismatch:
		return target == browsersession.ErrOriginMismatch
	case FetchFileSizeLimit:
		return target == ErrFetchSizeLimit
	case FetchFileTimeout:
		return target == ErrFetchTimeout
	case FetchFileBusy:
		return target == ErrFetchBusy
	case FetchFileRequestRefused:
		return target == ErrUnsafeFetchURL
	default:
		return false
	}
}

// AsFetchFileDiagnostic extracts the closed diagnostic a fetch-file caller may
// render. An error that is not already sealed collapses to FetchFileUnverifiable
// instead of being formatted, so a missed conversion fails closed rather than
// becoming the next leak.
func AsFetchFileDiagnostic(err error) FetchFileDiagnostic {
	var diagnostic FetchFileDiagnostic
	if errors.As(err, &diagnostic) {
		return NewFetchFileDiagnostic(diagnostic.code)
	}
	return NewFetchFileDiagnostic(FetchFileUnverifiable)
}

// sealFetchFileError is the mandatory outer normalizer for Session.FetchFile.
// It inspects the lower-layer error only to choose a fixed code and then drops
// it. An unrecognized error becomes FetchFileUnverifiable, so an internal branch
// that forgets to classify itself degrades to a safe refusal instead of opening
// a bypass.
func sealFetchFileError(err error) error {
	if err == nil {
		return nil
	}
	var sealed FetchFileDiagnostic
	if errors.As(err, &sealed) {
		return NewFetchFileDiagnostic(sealed.code)
	}
	return NewFetchFileDiagnostic(classifyFetchFileErrorCode(err))
}

func classifyFetchFileErrorCode(err error) FetchFileDiagnosticCode {
	switch {
	case errors.Is(err, ErrFetchBusy):
		return FetchFileBusy
	case errors.Is(err, ErrFetchSizeLimit):
		return FetchFileSizeLimit
	case errors.Is(err, ErrFetchTimeout), errors.Is(err, context.DeadlineExceeded):
		return FetchFileTimeout
	case errors.Is(err, ErrUnsafeFetchURL):
		return FetchFileRequestRefused
	case errors.Is(err, browsersession.ErrOriginMismatch):
		return FetchFileOriginMismatch
	case errors.Is(err, browsersession.ErrTargetMissing):
		return FetchFileTargetMissing
	case errors.Is(err, ErrPrivateTransport):
		return classifyPrivateTransportCode(err)
	case errors.Is(err, browsersession.ErrUnreadableResponse):
		return FetchFileResponseUnverifiable
	default:
		return FetchFileUnverifiable
	}
}

// classifyPrivateTransportCode reads the transport's own fixed kind vocabulary.
// The kind is chosen in Go and never carries child bytes, and it is consumed
// here only to pick a literal: the inspected error itself is discarded.
func classifyPrivateTransportCode(err error) FetchFileDiagnosticCode {
	var transport *PrivateTransportError
	if !errors.As(err, &transport) {
		return FetchFileTransportFailed
	}
	switch transport.Kind {
	case PrivateTransportChildUnavailable:
		return FetchFileTransportUnavailable
	case PrivateTransportChildExit, PrivateTransportExecuteFailed:
		return FetchFileTransportFailed
	default:
		return FetchFileResponseUnverifiable
	}
}
