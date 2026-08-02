package docsanitize

import "time"

const (
	SchemaVersion            = 1
	DefaultMaxInputBytes     = int64(50 << 20)
	DefaultMaxExtractedBytes = int64(20 << 20)
)

type Limits struct {
	MaxInputBytes     int64
	MaxExtractedBytes int64
}

func DefaultLimits() Limits {
	return Limits{
		MaxInputBytes:     DefaultMaxInputBytes,
		MaxExtractedBytes: DefaultMaxExtractedBytes,
	}
}

type Options struct {
	Limits       Limits
	CustomValues []string
}

type CategoryStats struct {
	Occurrences int `json:"occurrences"`
	Unique      int `json:"unique"`
}

type Report struct {
	SchemaVersion  int                      `json:"schema_version"`
	GeneratedAt    time.Time                `json:"generated_at"`
	SourceSHA256   string                   `json:"source_sha256"`
	InputFormat    string                   `json:"input_format"`
	Extractor      string                   `json:"extractor"`
	OutputEncoding string                   `json:"output_encoding"`
	ExtractedBytes int                      `json:"extracted_bytes"`
	SanitizedBytes int                      `json:"sanitized_bytes"`
	RedactionTotal int                      `json:"redaction_total"`
	Redactions     map[string]CategoryStats `json:"redactions"`
	Warnings       []string                 `json:"warnings,omitempty"`
}

type Result struct {
	Text   string
	Report Report
}

type extractedDocument struct {
	Text         string
	Format       string
	Extractor    string
	SourceSHA256 string
	Warnings     []string
}
