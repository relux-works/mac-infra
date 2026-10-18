package firewallwatch

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type Config struct {
	Schema            string   `json:"schema"`
	StateDir          string   `json:"state_dir"`
	MaxEntries        int      `json:"max_entries"`
	RetentionDays     int      `json:"retention_days"`
	NettopInterval    string   `json:"nettop_interval"`
	DenySpikeCount    int      `json:"deny_spike_count"`
	DenySpikeWindow   string   `json:"deny_spike_window"`
	K                 int      `json:"k"`
	NoveltySimilarity *float64 `json:"novelty_similarity"`
	ClassifierTimeout string   `json:"classifier_timeout"`
	LlamaServer       string   `json:"llama_server"`
	Model             string   `json:"model"`
	ModelSHA256       string   `json:"model_sha256"`
	LabelledPool      string   `json:"labelled_pool"`
	SaveInterval      string   `json:"save_interval"`
	SignerFailureTTL  string   `json:"signer_failure_ttl"`
	MaxStateBytes     int64    `json:"max_state_bytes"`
	MaxModelBytes     int64    `json:"max_model_bytes"`
}

func ownedRegular(f *os.File) error {
	s, e := f.Stat()
	if e != nil {
		return e
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !s.Mode().IsRegular() || !ok || int(st.Uid) != os.Getuid() || s.Mode().Perm()&0022 != 0 {
		return errors.New("must be a regular file owned by caller and not group/world writable")
	}
	return nil
}
func LoadConfig(path string) (Config, error) {
	var c Config
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	if e = ownedRegular(f); e != nil {
		return c, e
	}
	raw, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil {
		return c, e
	}
	if len(raw) > 65536 {
		return c, errors.New("config too large")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	if d.Decode(new(any)) != io.EOF {
		return c, errors.New("trailing config data")
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	if c.Schema != "mac-infra.firewall-watch/v1" || c.MaxStateBytes < 1 || c.MaxStateBytes > 1<<30 || c.MaxModelBytes < 1 || c.MaxModelBytes > 1<<40 || c.MaxEntries < 1 || c.MaxEntries > 100000 || c.RetentionDays > 3650 || c.RetentionDays < 1 || c.DenySpikeCount < 1 || c.K < 1 || c.NoveltySimilarity == nil || math.IsNaN(*c.NoveltySimilarity) || *c.NoveltySimilarity <= 0 || *c.NoveltySimilarity > 1 {
		return errors.New("missing or invalid required config field")
	}
	for _, p := range []string{c.StateDir, c.LlamaServer, c.Model, c.LabelledPool} {
		if !filepath.IsAbs(p) {
			return errors.New("all paths must be absolute")
		}
	}
	for _, v := range []string{c.NettopInterval, c.DenySpikeWindow, c.ClassifierTimeout, c.SaveInterval, c.SignerFailureTTL} {
		if d, e := time.ParseDuration(v); e != nil || d <= 0 {
			return errors.New("required durations must be positive Go durations")
		}
	}
	h, e := hex.DecodeString(c.ModelSHA256)
	if e != nil || len(h) != 32 {
		return errors.New("model_sha256 must be 64 hex digits")
	}
	return nil
}
func (c Config) SocketPath() string   { return filepath.Join(c.StateDir, "llm.sock") }
func (c Config) Backend() string      { return "http://llama" }
func duration(s string) time.Duration { d, _ := time.ParseDuration(s); return d }
