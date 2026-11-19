package javatruststore

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"time"
)

const (
	ExitOK          = 0
	ExitUsage       = 2
	ExitRefusal     = 3
	ExitOperational = 4
)

const (
	CauseInvalidUsage         = "invalid_usage"
	CauseInvalidFingerprint   = "invalid_fingerprint"
	CauseNoMatch              = "no_match"
	CauseMultipleMatches      = "multiple_matches"
	CauseMalformedSource      = "malformed_certificate_source"
	CauseNotCA                = "not_ca"
	CauseNotSelfSigned        = "not_self_signed_root"
	CauseNotYetValid          = "not_yet_valid"
	CauseExpired              = "expired"
	CauseOutputExists         = "output_exists"
	CauseSymlink              = "symlink"
	CauseOutsideProject       = "outside_project"
	CauseParentMissing        = "output_parent_missing"
	CauseStaleCACerts         = "stale_cacerts"
	CauseStaleRoot            = "stale_root"
	CauseStaleManifest        = "stale_manifest"
	CauseStoreModified        = "store_modified"
	CauseStorePermissions     = "store_permissions"
	CauseUnsupportedOS        = "unsupported_platform"
	CauseKeychainRead         = "keychain_read_failed"
	CauseCACertsRead          = "cacerts_unreadable"
	CauseKeytoolFailed        = "keytool_failed"
	CauseStoreType            = "unsupported_store_type"
	CauseGradleWrapper        = "gradle_wrapper_missing"
	CauseGradleConfig         = "gradle_config_conflict"
	CauseGradleDaemonCriteria = "gradle_daemon_criteria_unsupported"
	CauseProcessFailed        = "process_failed"
)

const (
	storePassword  = "changeit"
	storeFileName  = "truststore"
	manifestName   = "manifest.json"
	rootFileName   = ".selected-root.pem"
	gradleHomeName = "gradle-user-home"
)

// Failure contains a stable public cause while keeping raw paths and command output private.
type Failure struct {
	Code string
	Exit int
	Err  error
}

func (e *Failure) Error() string { return e.Code }

func (e *Failure) Unwrap() error { return e.Err }

func refusal(code string, err error) error {
	return &Failure{Code: code, Exit: ExitRefusal, Err: err}
}

func invalid(code string, err error) error {
	return &Failure{Code: code, Exit: ExitUsage, Err: err}
}

func operational(code string, err error) error {
	return &Failure{Code: code, Exit: ExitOperational, Err: err}
}

func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var failure *Failure
	if errors.As(err, &failure) {
		return failure.Exit
	}
	return ExitOperational
}

func Cause(err error) string {
	var failure *Failure
	if errors.As(err, &failure) {
		return failure.Code
	}
	return CauseProcessFailed
}

type Options struct {
	ProjectDir  string
	JavaHome    string
	Fingerprint string
	OutputDir   string
}

type Manifest struct {
	Schema        int    `json:"schema"`
	CACertsSHA256 string `json:"cacerts_sha256"`
	RootSHA256    string `json:"root_sha256"`
	StoreSHA256   string `json:"store_sha256"`
	StoreType     string `json:"store_type"`
}

type StoreInfo struct {
	ProjectDir string
	JavaHome   string
	OutputDir  string
	StorePath  string
	StoreType  string
	GradleHome string
}

type CertificateSource interface {
	Certificates(context.Context) ([]*x509.Certificate, error)
}

type CertificateSourceFunc func(context.Context) ([]*x509.Certificate, error)

func (f CertificateSourceFunc) Certificates(ctx context.Context) ([]*x509.Certificate, error) {
	return f(ctx)
}

type CommandRunner interface {
	CombinedOutput(context.Context, string, []string, string, []string) ([]byte, error)
}

type ProcessRunner interface {
	Run(context.Context, string, []string, string, []string, io.Reader, io.Writer, io.Writer) error
}

type StoreImporter interface {
	Import(context.Context, string, string, string, string) (string, error)
}

type Tool struct {
	Source    CertificateSource
	Commands  CommandRunner
	Processes ProcessRunner
	Importer  StoreImporter
	Now       func() time.Time
}
