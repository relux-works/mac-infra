package keyvault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SchemaVersion is the record schema this revision writes.
const SchemaVersion = 2

// Record is the schema-2 description of one vault item. It is stored as JSON
// in the item's kSecAttrApplicationTag so it cannot drift from the key on
// delete or rotate (STORY-260915-3r0ys5_key-record-model-v2.md, consolidated).
// label, fingerprint, exposure and operations are derived on every read and
// never stored.
type Record struct {
	Schema      int            `json:"schema"`
	Kind        string         `json:"kind"`
	Service     string         `json:"service"`
	Purpose     string         `json:"purpose"`
	Version     int            `json:"version"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Algorithm   string         `json:"algorithm"`
	Store       StoreKind      `json:"store"`
	Extraction  string         `json:"extraction"`
	Usages      []string       `json:"usages"`
	Format      Format         `json:"format"`
	Created     Time           `json:"created"`
	Origin      Origin         `json:"origin"`
	Issuer      *Issuer        `json:"issuer"`
	Validity    Validity       `json:"validity"`
	Meta        map[string]any `json:"meta"`
	// UserPresence records the biometry/passcode policy requested at init so
	// rotate reproduces it instead of weakening it. Never true on an
	// unprovisioned binary (-34018).
	UserPresence bool `json:"user_presence,omitempty"`
}

// Format names the default representations a command emits for the item;
// which keys are allowed depends on the kind.
type Format struct {
	Public    string `json:"public,omitempty"`
	Signature string `json:"signature,omitempty"`
	Envelope  string `json:"envelope,omitempty"`
}

// Origin records who put the item into the vault and how; the vault sets
// it, never the user.
type Origin struct {
	User   string `json:"user"`
	Host   string `json:"host"`
	Tool   string `json:"tool"`
	Source string `json:"source"`
}

// Issuer is the X.509 issuer of a certificate; nil for every other kind.
type Issuer struct {
	DN          string `json:"dn"`
	Fingerprint string `json:"fingerprint"`
}

// Validity bounds the item; nil means unbounded.
type Validity struct {
	NotBefore *Time `json:"not_before"`
	NotAfter  *Time `json:"not_after"`
}

// Time marshals as RFC3339 in UTC, or null when zero.
type Time struct{ time.Time }

// NewTime truncates t to whole UTC seconds.
func NewTime(t time.Time) Time { return Time{t.UTC().Truncate(time.Second)} }

func (t Time) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(t.UTC().Format(time.RFC3339))
}

func (t *Time) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*t = Time{}
		return nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	parsed, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return err
	}
	*t = NewTime(parsed)
	return nil
}

// Model vocabulary. Values outside these sets are refused before any
// Security.framework call; a known-but-unavailable value is refused with its
// own reason, never mapped to a neighbour.
const (
	KindKey         = "key"
	KindPublicKey   = "public-key"
	KindCertificate = "certificate"
	KindSecret      = "secret"

	AlgorithmECP256    = "ec-p256"
	AlgorithmAES256GCM = "aes-256-gcm"
	AlgorithmOpaque    = "opaque"
	AlgorithmECP384    = "ec-p384"
	AlgorithmRSA3072   = "rsa-3072"
	AlgorithmEd25519   = "ed25519"

	ExposureNever   = "never"
	ExposureProcess = "process"

	ExtractionNone  = "none"
	ExtractionHuman = "human"
	ExtractionAgent = "agent"

	FormatPublicSPKIDER = "spki-der"
	FormatPublicSPKIPEM = "spki-pem"
	FormatPublicJWK     = "jwk"

	FormatSignatureDERLowS = "ecdsa-der-low-s"
	FormatSignatureRaw     = "ecdsa-raw"

	SourceGenerated = "generated"

	// Unknown is what a v1 or unreadable record reports for fields it does
	// not carry; it is never upgraded silently.
	Unknown = "unknown"
)

var (
	kinds       = []string{KindKey, KindPublicKey, KindCertificate, KindSecret}
	extractions = []string{ExtractionNone, ExtractionHuman, ExtractionAgent}
	// Usages the policy filter understands.
	Usages           = []string{"sign", "verify", "wrap", "encrypt", "decrypt", "attest"}
	formatsPublic    = []string{FormatPublicSPKIDER, FormatPublicSPKIPEM, FormatPublicJWK}
	formatsSignature = []string{FormatSignatureDERLowS, FormatSignatureRaw}
	// ReservedMetaNames are every top-level record name plus the derived
	// names a read prints; none may appear inside meta.
	ReservedMetaNames = []string{"schema", "kind", "service", "purpose", "version", "title", "description", "algorithm", "store", "extraction", "usages", "format", "created", "origin", "issuer", "validity", "meta", "user_presence", "label", "fingerprint", "exposure", "operations", "findings"}
)

// MaxTitleLength bounds title; MaxNameLength bounds service and purpose.
const (
	MaxTitleLength = 80
	MaxNameLength  = 40
)

var namePattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// Refusal codes raised by record validation and the rotate/meta gates.
const (
	CodeInvalidService        = "invalid_service"
	CodeInvalidPurpose        = "invalid_purpose"
	CodeInvalidKind           = "invalid_kind"
	CodeUnsupportedKind       = "unsupported_kind"
	CodeInvalidAlgorithm      = "invalid_algorithm"
	CodeUnsupportedAlgorithm  = "unsupported_algorithm"
	CodeInvalidUsages         = "invalid_usages"
	CodeInvalidFormat         = "invalid_format"
	CodeInvalidExtraction     = "invalid_extraction"
	CodeInvalidGenerate       = "invalid_generate"
	CodeInvalidMeta           = "invalid_meta"
	CodeInvalidTitle          = "invalid_title"
	CodeInvalidIssuer         = "invalid_issuer"
	CodeInvalidValidity       = "invalid_validity"
	CodeMetadataUnknown       = "metadata_unknown"
	CodeUnsupportedPrimitive  = "unsupported_primitive"
	FindingValidityExpired    = "validity_expired"
	FindingRecordUnreadable   = "record_unreadable"
	hintFixInputNoSecurityCal = "nothing was created or changed; fix the input and rerun"
)

func contains(set []string, value string) bool {
	for _, item := range set {
		if item == value {
			return true
		}
	}
	return false
}

// ValidateName checks a service or purpose name.
func ValidateName(field, code, value string) error {
	if value == "" || !namePattern.MatchString(value) || len(value) > MaxNameLength {
		return &Refusal{Code: code, Message: fmt.Sprintf("%s %q must match %s and be 1-%d characters", field, value, namePattern, MaxNameLength), Hint: hintFixInputNoSecurityCal}
	}
	return nil
}

// ValidateKind checks a record kind against the closed vocabulary; every
// CLI path that takes --kind (addresses and the list filter) goes through
// it before any Security call (review F10).
func ValidateKind(kind string) error {
	if !contains(kinds, kind) {
		return &Refusal{Code: CodeInvalidKind, Message: fmt.Sprintf("kind %q is not one of %s", kind, strings.Join(kinds, ", ")), Hint: hintFixInputNoSecurityCal}
	}
	return nil
}

// ValidateNew checks a record the vault is about to create: the closed
// kind vocabulary, the creation scope of this revision, then every row of
// the per-kind invariant table (invariants.go). Every check runs on the
// caller's input alone: nothing here touches Security.framework, and the
// first failing field is refused with its own code.
func ValidateNew(rec Record) error {
	if err := ValidateName("service", CodeInvalidService, rec.Service); err != nil {
		return err
	}
	if err := ValidateName("purpose", CodeInvalidPurpose, rec.Purpose); err != nil {
		return err
	}
	if err := ValidateKind(rec.Kind); err != nil {
		return err
	}
	if rec.Kind != KindKey {
		return &Refusal{Code: CodeUnsupportedKind, Message: fmt.Sprintf("kind %q is not implemented in this revision; only kind key is created", rec.Kind), Hint: "public-key, certificate and secret arrive with T4-T7; nothing was created"}
	}
	return ValidateRecord(rec)
}

// ValidateMeta refuses reserved names and values that are not string, number
// or bool.
func ValidateMeta(meta map[string]any) error {
	for name, value := range meta {
		if err := ValidateMetaEntry(name, value); err != nil {
			return err
		}
	}
	return nil
}

// ValidateMetaEntry checks one meta name/value pair.
func ValidateMetaEntry(name string, value any) error {
	if name == "" {
		return &Refusal{Code: CodeInvalidMeta, Message: "meta names must not be empty", Hint: hintFixInputNoSecurityCal}
	}
	if contains(ReservedMetaNames, name) {
		return &Refusal{Code: CodeInvalidMeta, Message: fmt.Sprintf("meta name %q is reserved for the record model", name), Hint: "a field the vault reacts to belongs in the model, not in meta; pick another name"}
	}
	switch value.(type) {
	case string, bool, float64, int, int64, json.Number:
		return nil
	default:
		return &Refusal{Code: CodeInvalidMeta, Message: fmt.Sprintf("meta %q has unsupported type %T", name, value), Hint: "only string, number and bool values are allowed"}
	}
}

// Label derives the keychain label of the record:
// works.relux.mac-keyvault.<kind>.<service>.<purpose>.v<N>, .v<N> always present.
func (r Record) Label() string {
	return Address{Kind: r.Kind, Service: r.Service, Purpose: r.Purpose, Version: r.Version}.Label()
}

// Address names the record for messages.
func (r Record) Address() string {
	return r.Service + "/" + r.Purpose
}

// SortedUsages returns the usages in the canonical order.
func (r Record) SortedUsages() []string {
	out := append([]string(nil), r.Usages...)
	sort.Slice(out, func(i, j int) bool { return indexOf(Usages, out[i]) < indexOf(Usages, out[j]) })
	return out
}

func indexOf(set []string, value string) int {
	for i, item := range set {
		if item == value {
			return i
		}
	}
	return len(set)
}

// EncodeRecord serialises the record for the application tag.
func EncodeRecord(rec Record) ([]byte, error) {
	if rec.Meta == nil {
		rec.Meta = map[string]any{}
	}
	rec.Usages = rec.SortedUsages()
	return json.Marshal(rec)
}

// legacyTagVersion is the rev1 application tag prefix.
const legacyTagVersion = "mac-keyvault/1"

// DecodeSingleJSON decodes exactly one JSON document into v with numbers
// kept as json.Number. A second document, a trailing token or trailing
// garbage after the first document is an error; surrounding whitespace is
// not. It is the one document-boundary rule for every JSON the vault reads:
// --meta-json and --json-value input as well as the persisted record tag.
//
// The decoder is also strict about members: a JSON object member that no
// struct field of v (top-level or nested) declares is an error, so a
// persisted record carrying a field the schema does not define is a read
// failure, never a readable record with the field silently erased before
// ValidateStored can see it (review F14). Open maps such as Record.Meta and
// the --meta-json / --json-value targets (map[string]any, any) are not
// closed by this; DisallowUnknownFields only constrains struct targets.
func DecodeSingleJSON(data []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("unexpected data after the JSON document")
		}
		return err
	}
	return nil
}

// DecodeRecord reads an application tag. A schema-2 JSON tag round-trips; a
// rev1 tag is reported as schema 1 with service and purpose unknown; an
// absent tag is schema 0 with everything unknown; a tag that is present but
// unreadable is schema 0 with a non-empty problem so the caller can tell a
// read failure from an absence. Nothing is upgraded.
func DecodeRecord(tag []byte) (rec Record, problem string) {
	unknown := Record{Schema: 0, Kind: Unknown, Service: Unknown, Purpose: Unknown, Algorithm: Unknown, Store: StoreUnknown, Extraction: Unknown, Meta: map[string]any{}}
	text := strings.TrimSpace(string(tag))
	switch {
	case text == "":
		return unknown, ""
	case strings.HasPrefix(text, "{"):
		// Numbers inside meta are decoded as json.Number so a value such
		// as 9007199254740993 round-trips digit-exact instead of being
		// rounded through float64 (review F11).
		// The tag must be exactly one document: a record followed by a
		// second document, token or garbage is a read failure, never a
		// readable record (review F12, same class as F6 for --meta-json;
		// both boundaries share DecodeSingleJSON).
		var decoded Record
		if err := DecodeSingleJSON([]byte(text), &decoded); err != nil {
			return unknown, "record tag is not valid JSON: " + err.Error()
		}
		if decoded.Schema != SchemaVersion {
			return unknown, fmt.Sprintf("record schema %d is not %d", decoded.Schema, SchemaVersion)
		}
		if decoded.Meta == nil {
			decoded.Meta = map[string]any{}
		}
		return decoded, ""
	case strings.HasPrefix(text, legacyTagVersion+" ") || text == legacyTagVersion:
		// The v1 tag carries only store and created; kind and algorithm
		// are reported unknown rather than inferred from what rev1 used
		// to generate, so no registry row matches and no operation is
		// advertised.
		rec := unknown
		rec.Schema = 1
		for _, field := range strings.Fields(text)[1:] {
			switch {
			case strings.HasPrefix(field, "store="):
				switch store := StoreKind(strings.TrimPrefix(field, "store=")); store {
				case StoreKeychain, StoreEnclave:
					rec.Store = store
				}
			case strings.HasPrefix(field, "created="):
				if parsed, err := time.Parse(time.RFC3339, strings.TrimPrefix(field, "created=")); err == nil {
					rec.Created = NewTime(parsed)
				}
			}
		}
		return rec, ""
	default:
		return unknown, "record tag has an unknown format"
	}
}

// Address selects a vault item: kind, service, purpose and optionally one
// version (0 = the newest). It is the only way a command names an item; a
// raw label is refused before any Security call (review F1, model §1).
type Address struct {
	Kind    string
	Service string
	Purpose string
	Version int
}

// ParseAddress parses <service>/<purpose> CLI input with the kind and
// version flags. Input without a slash — a raw label, inside or outside the
// prefix — is foreign_label.
func ParseAddress(input, kind string, version int) (Address, error) {
	service, purpose, ok := strings.Cut(input, "/")
	if !ok {
		return Address{}, &Refusal{Code: CodeForeignLabel, Message: fmt.Sprintf("%q is not a <service>/<purpose> address; raw labels are not accepted", input), Hint: "addresses are <service>/<purpose>, optionally with --kind and --version; the label is derived by the vault"}
	}
	if err := ValidateName("service", CodeInvalidService, service); err != nil {
		return Address{}, err
	}
	if err := ValidateName("purpose", CodeInvalidPurpose, purpose); err != nil {
		return Address{}, err
	}
	if err := ValidateKind(kind); err != nil {
		return Address{}, err
	}
	if version < 0 {
		return Address{}, &Refusal{Code: CodeInvalidPurpose, Message: fmt.Sprintf("version %d must be at least 1", version), Hint: hintFixInputNoSecurityCal}
	}
	addr := Address{Kind: kind, Service: service, Purpose: purpose, Version: version}
	if err := RequireOwnLabel(addr.Label()); err != nil {
		return Address{}, err
	}
	return addr, nil
}

// Label derives works.relux.mac-keyvault.<kind>.<service>.<purpose>.v<N>;
// version 0 (newest) yields no suffix and is never a real label.
func (a Address) Label() string {
	label := LabelPrefix + a.Kind + "." + a.Service + "." + a.Purpose
	if a.Version > 0 {
		label += ".v" + strconv.Itoa(a.Version)
	}
	return label
}

// ParseLabel inverts Label for items read back from the keychain; ok is
// false for any label that is not exactly prefix.kind.service.purpose.vN.
func ParseLabel(label string) (Address, bool) {
	if RequireOwnLabel(label) != nil {
		return Address{}, false
	}
	parts := strings.Split(strings.TrimPrefix(label, LabelPrefix), ".")
	if len(parts) != 4 || !strings.HasPrefix(parts[3], "v") {
		return Address{}, false
	}
	version, err := strconv.Atoi(strings.TrimPrefix(parts[3], "v"))
	if err != nil || version < 1 || !contains(kinds, parts[0]) || !namePattern.MatchString(parts[1]) || !namePattern.MatchString(parts[2]) {
		return Address{}, false
	}
	return Address{Kind: parts[0], Service: parts[1], Purpose: parts[2], Version: version}, true
}

// String renders the address for messages.
func (a Address) String() string {
	s := a.Service + "/" + a.Purpose
	if a.Kind != KindKey {
		s += " (kind " + a.Kind + ")"
	}
	if a.Version > 0 {
		s += " v" + strconv.Itoa(a.Version)
	}
	return s
}

// Matches reports whether key is one generation of the address, judged by
// the label alone so that an item with an unreadable record is still found.
func (a Address) Matches(key Key) bool {
	parsed, ok := ParseLabel(key.Label)
	if !ok {
		return false
	}
	return parsed.Kind == a.Kind && parsed.Service == a.Service && parsed.Purpose == a.Purpose && (a.Version == 0 || parsed.Version == a.Version)
}
