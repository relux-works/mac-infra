package keyvault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The Secure Enclave store keeps each key as a CryptoKit
// SecureEnclave.P256.Signing.PrivateKey blob (dataRepresentation) in a
// tool-owned file. The blob is wrapped by this device's Secure Enclave and
// useless anywhere else; the private half never exists outside it. This
// route needs no keychain entitlement, which the login-keychain route
// (security_darwin.c) refuses with -34018 for --enclave and --user-presence.
// The Swift helper mac-keyvault-enclave performs every Secure Enclave call;
// this file owns the files, the policy and the checks around it.

// EnclaveFileFormat names the file layout below.
const EnclaveFileFormat = "mac-keyvault-enclave/1"

// enclaveFileMax bounds what is read back: a blob is about 0.5 KiB and the
// record a few KiB.
const enclaveFileMax = 64 * 1024

// Presence modes the helper understands.
const (
	enclavePresenceNone     = "none"
	enclavePresenceBiometry = "biometry-current-set"
	enclavePresenceRequired = "required"
)

// enclaveFile is one key on disk. Tag is the schema-2 record, as the
// keychain application tag carries it; Point is the X9.63 public half the
// helper returned at creation.
type enclaveFile struct {
	Format string `json:"format"`
	Label  string `json:"label"`
	Tag    string `json:"tag"`
	Point  []byte `json:"point"`
	Blob   []byte `json:"blob"`
}

// EnclaveRequest is one helper call; byte fields travel as base64.
type EnclaveRequest struct {
	Op       string `json:"op"`
	Presence string `json:"presence,omitempty"`
	Blob     []byte `json:"blob,omitempty"`
	Digest   []byte `json:"digest,omitempty"`
	Reason   string `json:"reason,omitempty"`
	// Interaction "none" forbids the presence prompt: a presence key then
	// refuses instead of asking.
	Interaction string `json:"interaction,omitempty"`
}

// EnclaveResponse is the helper's answer; Error is set exactly when the
// helper failed.
type EnclaveResponse struct {
	Blob             []byte              `json:"blob,omitempty"`
	Point            []byte              `json:"point,omitempty"`
	DER              []byte              `json:"der,omitempty"`
	PresenceEnforced *bool               `json:"presence_enforced,omitempty"`
	Error            *EnclaveHelperError `json:"error,omitempty"`
}

// EnclaveHelperError is a failure the helper reported: a short code and the
// OSStatus it maps to (errSecInteractionNotAllowed when presence was needed
// and not given, errSecUserCanceled for a canceled prompt).
type EnclaveHelperError struct {
	Code    string `json:"code"`
	Status  int    `json:"status"`
	Message string `json:"message"`
}

func (e *EnclaveHelperError) Error() string {
	return fmt.Sprintf("mac-keyvault-enclave %s: %s", e.Code, e.Message)
}

// EnclaveHelper runs one request. interactive is true only for a signature
// that may show the Touch ID prompt, so the runner can allow it more time.
type EnclaveHelper interface {
	Call(req EnclaveRequest, interactive bool) (EnclaveResponse, error)
}

// ExecEnclaveHelper runs the mac-keyvault-enclave binary at Path.
type ExecEnclaveHelper struct {
	Path string
	// Timeout bounds a silent call, InteractiveTimeout a call that waits
	// for the owner's finger.
	Timeout            time.Duration
	InteractiveTimeout time.Duration
}

// Call writes the request to the helper's stdin and decodes one response.
func (h ExecEnclaveHelper) Call(req EnclaveRequest, interactive bool) (EnclaveResponse, error) {
	if !filepath.IsAbs(h.Path) {
		return EnclaveResponse{}, fmt.Errorf("enclave helper path %q is not absolute", h.Path)
	}
	if err := requireOwnedFile(h.Path, false); err != nil {
		return EnclaveResponse{}, fmt.Errorf("enclave helper: %w", err)
	}
	timeout := h.Timeout
	if interactive {
		timeout = h.InteractiveTimeout
	}
	input, err := json.Marshal(req)
	if err != nil {
		return EnclaveResponse{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.Path)
	cmd.Stdin = bytes.NewReader(input)
	var stdout bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, n: enclaveFileMax}
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return EnclaveResponse{}, &StatusError{Op: "enclave " + req.Op + " (timed out)", Status: errSecUserCanceled}
	}
	var resp EnclaveResponse
	if err := DecodeSingleJSON(bytes.TrimSpace(stdout.Bytes()), &resp); err != nil {
		if runErr != nil {
			return EnclaveResponse{}, fmt.Errorf("enclave helper %s: %w", req.Op, runErr)
		}
		return EnclaveResponse{}, fmt.Errorf("enclave helper %s: unreadable response: %w", req.Op, err)
	}
	if resp.Error != nil {
		return EnclaveResponse{}, resp.Error
	}
	if runErr != nil {
		return EnclaveResponse{}, fmt.Errorf("enclave helper %s: %w", req.Op, runErr)
	}
	return resp, nil
}

const errSecUserCanceled = -128

type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > l.n {
		return 0, errors.New("enclave helper output exceeds the limit")
	}
	l.n -= len(p)
	return l.w.Write(p)
}

// EnclaveStore is the Backend for store "enclave": one file per label in
// Dir, every Secure Enclave call through Helper.
type EnclaveStore struct {
	Dir    string
	Helper EnclaveHelper
	// NonInteractive never shows the Touch ID prompt: a presence key then
	// refuses with errSecInteractionNotAllowed. Production leaves it false.
	NonInteractive bool
	// err is a construction failure of the directory (no home directory),
	// reported by every call. helperErr is a missing or unresolvable helper:
	// keys are still listed, described and deleted, but nothing is created
	// or signed and Serves reports the store as not served.
	err       error
	helperErr error
}

// NewEnclaveStore returns a store over dir with helper.
func NewEnclaveStore(dir string, helper EnclaveHelper) *EnclaveStore {
	return &EnclaveStore{Dir: dir, Helper: helper}
}

// DefaultEnclaveStore is the production store: files under
// DefaultEnclaveDir, the helper mac-keyvault-enclave next to the running
// executable (symlinks resolved), never looked up on PATH.
func DefaultEnclaveStore() *EnclaveStore {
	dir, err := DefaultEnclaveDir()
	if err != nil {
		return &EnclaveStore{err: fmt.Errorf("enclave store: %w", err)}
	}
	self, err := os.Executable()
	if err == nil {
		self, err = filepath.EvalSymlinks(self)
	}
	if err != nil {
		return &EnclaveStore{Dir: dir, helperErr: fmt.Errorf("enclave helper: %w", err)}
	}
	helper := ExecEnclaveHelper{Path: filepath.Join(filepath.Dir(self), "mac-keyvault-enclave"), Timeout: 15 * time.Second, InteractiveTimeout: 60 * time.Second}
	store := NewEnclaveStore(dir, helper)
	if err := requireOwnedFile(helper.Path, false); err != nil {
		store.helperErr = fmt.Errorf("enclave helper %s: %w", helper.Path, err)
	}
	return store
}

// Serves reports whether the store can create and sign: its directory and
// its helper both resolved.
func (s *EnclaveStore) Serves() bool {
	return s != nil && s.err == nil && s.helperErr == nil && s.Helper != nil
}

func (s *EnclaveStore) usable() error {
	if s.err != nil {
		return s.err
	}
	if s.helperErr != nil {
		return s.helperErr
	}
	if s.Helper == nil {
		return errors.New("enclave store: no helper")
	}
	return nil
}

// DefaultEnclaveDir sits next to the init lock.
func DefaultEnclaveDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "mac-infra", "keyvault", "enclave"), nil
}

func (s *EnclaveStore) path(label string) (string, error) {
	if err := RequireOwnLabel(label); err != nil {
		return "", err
	}
	if !labelPattern.MatchString(label) || strings.Contains(label, "..") {
		return "", fmt.Errorf("enclave store: label %q cannot name a file", label)
	}
	return filepath.Join(s.Dir, label+".json"), nil
}

// Create asks the helper for a new Secure Enclave key and stores it. A key
// whose measured presence policy differs from the requested one is refused
// and never stored: the record must not claim a protection the key lacks.
func (s *EnclaveStore) Create(opts CreateOptions) (Item, error) {
	if err := s.usable(); err != nil {
		return Item{}, err
	}
	if opts.Store != StoreEnclave {
		return Item{}, fmt.Errorf("enclave store: cannot create store %q", opts.Store)
	}
	path, err := s.path(opts.Label)
	if err != nil {
		return Item{}, err
	}
	if err := s.ensureDir(); err != nil {
		return Item{}, err
	}
	if _, err := os.Lstat(path); err == nil {
		return Item{}, &StatusError{Op: "create (Secure Enclave)", Status: -25299}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Item{}, fmt.Errorf("enclave store: %w", err)
	}
	presence := enclavePresenceNone
	if opts.UserPresence {
		presence = enclavePresenceBiometry
	}
	resp, err := s.Helper.Call(EnclaveRequest{Op: "create", Presence: presence}, false)
	if err != nil {
		return Item{}, enclaveError("create (Secure Enclave)", err)
	}
	if len(resp.Blob) == 0 || resp.PresenceEnforced == nil {
		return Item{}, untrusted(opts.Label, "the helper returned no blob or no presence verdict")
	}
	if *resp.PresenceEnforced != opts.UserPresence {
		return Item{}, untrusted(opts.Label, fmt.Sprintf("the new key enforces user presence = %t, the request asked for %t; nothing was stored", *resp.PresenceEnforced, opts.UserPresence))
	}
	spki, err := spkiFromPoint(resp.Point)
	if err != nil {
		return Item{}, untrusted(opts.Label, "the helper returned an invalid public key: "+err.Error())
	}
	file := enclaveFile{Format: EnclaveFileFormat, Label: opts.Label, Tag: string(opts.Tag), Point: resp.Point, Blob: resp.Blob}
	if err := s.write(path, file, false); err != nil {
		return Item{}, err
	}
	return Item{Label: opts.Label, Tag: opts.Tag, SPKI: spki}, nil
}

// List reads every key file. A file that is unsafe or unreadable is still
// listed under its label, with the reason as Problem and no record, so it
// can be seen and deleted but never used.
func (s *EnclaveStore) List() ([]Item, error) {
	if s.err != nil {
		return nil, s.err
	}
	if _, err := os.Lstat(s.Dir); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err := requireOwnedDir(s.Dir); err != nil {
		return nil, fmt.Errorf("enclave store: %w", err)
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, fmt.Errorf("enclave store: %w", err)
	}
	var items []Item
	for _, entry := range entries {
		label, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || RequireOwnLabel(label) != nil {
			continue
		}
		file, err := s.read(label)
		if err != nil {
			items = append(items, Item{Label: label, Problem: "enclave file refused: " + err.Error()})
			continue
		}
		spki, err := spkiFromPoint(file.Point)
		if err != nil {
			items = append(items, Item{Label: label, Problem: "enclave file refused: public key: " + err.Error()})
			continue
		}
		items = append(items, Item{Label: label, Tag: []byte(file.Tag), SPKI: spki})
	}
	return items, nil
}

// Has reports whether a key file exists under label.
func (s *EnclaveStore) Has(label string) bool {
	if s.err != nil {
		return false
	}
	path, err := s.path(label)
	if err != nil {
		return false
	}
	_, err = os.Lstat(path)
	return err == nil
}

// Delete removes the key file; the Secure Enclave key is gone with its blob.
func (s *EnclaveStore) Delete(label string) error {
	if s.err != nil {
		return s.err
	}
	path, err := s.path(label)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotFound
		}
		return fmt.Errorf("enclave store: %w", err)
	}
	return nil
}

// UpdateTag rewrites the record of a key; blob and public half stay.
func (s *EnclaveStore) UpdateTag(label string, tag []byte) error {
	if s.err != nil {
		return s.err
	}
	path, err := s.path(label)
	if err != nil {
		return err
	}
	file, err := s.read(label)
	if err != nil {
		return err
	}
	file.Tag = string(tag)
	return s.write(path, file, true)
}

// Sign signs digest with the key under label. The record's user_presence
// decides whether the helper must find presence enforced and ask for it;
// the public half of the blob must equal the stored one.
func (s *EnclaveStore) Sign(label string, digest []byte) ([]byte, error) {
	if err := s.usable(); err != nil {
		return nil, err
	}
	if len(digest) != DigestSize {
		return nil, ValidateDigest(digest)
	}
	file, err := s.read(label)
	if err != nil {
		return nil, err
	}
	rec, problem := DecodeRecord([]byte(file.Tag))
	if problem != "" || rec.Store != StoreEnclave {
		return nil, untrusted(label, "the stored record is unreadable or not an enclave record; nothing was signed")
	}
	presence := enclavePresenceNone
	if rec.UserPresence {
		presence = enclavePresenceRequired
	}
	reason := "mac-keyvault: sign with " + label
	if addr, ok := ParseLabel(label); ok {
		reason = fmt.Sprintf("mac-keyvault: sign with %s/%s v%d", addr.Service, addr.Purpose, addr.Version)
	}
	req := EnclaveRequest{Op: "sign", Blob: file.Blob, Digest: digest, Presence: presence, Reason: reason}
	if s.NonInteractive {
		req.Interaction = "none"
	}
	resp, err := s.Helper.Call(req, rec.UserPresence && !s.NonInteractive)
	if err != nil {
		return nil, enclaveError("sign", err)
	}
	if !bytes.Equal(resp.Point, file.Point) {
		return nil, untrusted(label, "the key blob does not belong to the stored public key; nothing was emitted")
	}
	if len(resp.DER) == 0 {
		return nil, untrusted(label, "the helper returned no signature")
	}
	return resp.DER, nil
}

// enclaveError keeps a helper OSStatus in the Security.framework status
// space (so Translate names it: errSecInteractionNotAllowed,
// errSecUserCanceled, ...), and reports a broken blob or an unenforced
// presence policy as untrusted output.
func enclaveError(op string, err error) error {
	var helper *EnclaveHelperError
	if !errors.As(err, &helper) {
		return err
	}
	switch helper.Code {
	case "presence_not_enforced", "invalid_blob":
		return &Refusal{Code: CodeSecurity, Failure: true, Message: fmt.Sprintf("Secure Enclave %s: %s", op, helper.Message), Hint: "describe the key; a blob that does not match its record is never used, delete --confirm it and init a fresh key"}
	}
	if helper.Status == 0 {
		return fmt.Errorf("Secure Enclave %s: %s", op, helper.Message)
	}
	return &StatusError{Op: op, Status: helper.Status}
}

func untrusted(label, message string) error {
	return &Refusal{Code: CodeSecurity, Failure: true, Message: fmt.Sprintf("%s: %s", label, message), Hint: "nothing was emitted; describe the key, delete --confirm it if its file was altered and init a fresh key"}
}

func (s *EnclaveStore) ensureDir() error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("enclave store: %w", err)
	}
	if err := requireOwnedDir(s.Dir); err != nil {
		return fmt.Errorf("enclave store: %w", err)
	}
	return nil
}

// read loads and checks one key file: a regular file, not a symlink, owned
// by this user, no group or other bits, bounded, one JSON document whose
// format and label match.
func (s *EnclaveStore) read(label string) (enclaveFile, error) {
	path, err := s.path(label)
	if err != nil {
		return enclaveFile{}, err
	}
	if err := requireOwnedDir(s.Dir); err != nil {
		return enclaveFile{}, fmt.Errorf("enclave store: %w", err)
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return enclaveFile{}, ErrNotFound
	}
	if err := requireOwnedFile(path, true); err != nil {
		return enclaveFile{}, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return enclaveFile{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, enclaveFileMax+1))
	if err != nil {
		return enclaveFile{}, err
	}
	if len(data) > enclaveFileMax {
		return enclaveFile{}, fmt.Errorf("%s exceeds %d bytes", filepath.Base(path), enclaveFileMax)
	}
	var file enclaveFile
	if err := DecodeSingleJSON(data, &file); err != nil {
		return enclaveFile{}, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	if file.Format != EnclaveFileFormat || file.Label != label || len(file.Blob) == 0 {
		return enclaveFile{}, fmt.Errorf("%s: format or label does not match its name", filepath.Base(path))
	}
	return file, nil
}

// write stores file atomically: a 0600 temporary file in Dir, synced, then
// linked to path (create, never replacing) or renamed over it (update).
func (s *EnclaveStore) write(path string, file enclaveFile, replace bool) error {
	data, err := json.Marshal(file)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.Dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("enclave store: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err == nil {
		if _, err = tmp.Write(data); err == nil {
			err = tmp.Sync()
		}
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("enclave store: %w", err)
	}
	if replace {
		err = os.Rename(tmp.Name(), path)
	} else {
		err = os.Link(tmp.Name(), path)
	}
	if err != nil {
		return fmt.Errorf("enclave store: %w", err)
	}
	return nil
}

// RoutedBackend serves the keychain and the Secure Enclave store as one
// Backend: create goes by the requested store, every other call by where the
// label lives. A label present in both stores is listed with a problem so the
// Manager never operates on it.
type RoutedBackend struct {
	Keychain Backend
	Enclave  *EnclaveStore
}

// Serves implements StoreServer: the keychain always, the enclave store when
// its helper resolved.
func (r RoutedBackend) Serves(store StoreKind) bool {
	switch store {
	case StoreKeychain:
		return true
	case StoreEnclave:
		return r.Enclave.Serves()
	}
	return false
}

func (r RoutedBackend) Create(opts CreateOptions) (Item, error) {
	if opts.Store == StoreEnclave {
		return r.Enclave.Create(opts)
	}
	return r.Keychain.Create(opts)
}

func (r RoutedBackend) List() ([]Item, error) {
	keychain, err := r.Keychain.List()
	if err != nil {
		return nil, err
	}
	enclave, err := r.Enclave.List()
	if err != nil {
		return nil, err
	}
	inKeychain := map[string]bool{}
	for _, item := range keychain {
		inKeychain[item.Label] = true
	}
	items := append([]Item{}, keychain...)
	for _, item := range enclave {
		if inKeychain[item.Label] {
			item = Item{Label: item.Label, Problem: "label exists in both the keychain and the enclave store"}
			for i := range items {
				if items[i].Label == item.Label {
					items[i] = Item{Label: item.Label, Problem: item.Problem}
				}
			}
		}
		items = append(items, item)
	}
	return items, nil
}

func (r RoutedBackend) Delete(label string) error {
	if r.Enclave.Has(label) {
		return r.Enclave.Delete(label)
	}
	return r.Keychain.Delete(label)
}

func (r RoutedBackend) UpdateTag(label string, tag []byte) error {
	if r.Enclave.Has(label) {
		return r.Enclave.UpdateTag(label, tag)
	}
	return r.Keychain.UpdateTag(label, tag)
}

func (r RoutedBackend) Sign(label string, digest []byte) ([]byte, error) {
	if r.Enclave.Has(label) {
		return r.Enclave.Sign(label, digest)
	}
	return r.Keychain.Sign(label, digest)
}
