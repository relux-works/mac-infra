// Package firewall manages the macOS application firewall from a reviewed,
// declarative config. Planning and applying run only inside the mac-infra-core
// root helper, which re-validates every request; clients only send the config.
//
// The global firewall state is not configurable: the package can turn the
// firewall on and keep it on, never off.
package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

const (
	SchemaV1       = "mac-infra.firewall/v1"
	ModeListed     = "listed"
	ModeExact      = "exact"
	MaxConfigBytes = 64 << 10
	MaxApps        = 256
	maxPathLength  = 1024
)

// Config is the operator-owned desired state. A nil toggle leaves that
// setting unmanaged; apps and services not listed are unmanaged unless
// apps.mode is exact.
type Config struct {
	Schema                string         `json:"schema"`
	Stealth               *bool          `json:"stealth,omitempty"`
	BlockAll              *bool          `json:"block_all,omitempty"`
	AllowSignedBuiltin    *bool          `json:"allow_signed_builtin,omitempty"`
	AllowSignedDownloaded *bool          `json:"allow_signed_downloaded,omitempty"`
	Apps                  AppsConfig     `json:"apps"`
	Services              ServicesConfig `json:"services"`
}

type AppsConfig struct {
	Mode  string   `json:"mode"`
	Allow []string `json:"allow"`
	Block []string `json:"block"`
}

type ServicesConfig struct {
	Disable []string `json:"disable"`
}

// ParseConfig accepts exactly one JSON object with known fields only, then
// validates it structurally. Host-dependent checks happen during planning.
func ParseConfig(data []byte) (Config, error) {
	if len(data) > MaxConfigBytes {
		return Config{}, fmt.Errorf("firewall config exceeds %d bytes", MaxConfigBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse firewall config: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("parse firewall config: trailing data after the config object")
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.Schema != SchemaV1 {
		return fmt.Errorf("firewall config schema must be %q", SchemaV1)
	}
	if c.Apps.Mode != ModeListed && c.Apps.Mode != ModeExact {
		return fmt.Errorf("apps.mode must be %q or %q", ModeListed, ModeExact)
	}
	if len(c.Apps.Allow)+len(c.Apps.Block) > MaxApps {
		return fmt.Errorf("firewall config lists more than %d apps", MaxApps)
	}
	seen := map[string]string{}
	for _, list := range []struct {
		name  string
		paths []string
	}{{"apps.allow", c.Apps.Allow}, {"apps.block", c.Apps.Block}} {
		for _, path := range list.paths {
			if err := validateAppPath(path); err != nil {
				return fmt.Errorf("%s: %w", list.name, err)
			}
			if previous, ok := seen[path]; ok {
				return fmt.Errorf("%s: %q is already listed in %s", list.name, path, previous)
			}
			seen[path] = list.name
		}
	}
	services := map[string]bool{}
	for _, name := range c.Services.Disable {
		if _, ok := LookupService(name); !ok {
			return fmt.Errorf("services.disable: %q is not an allowlisted service", name)
		}
		if services[name] {
			return fmt.Errorf("services.disable: %q is listed twice", name)
		}
		services[name] = true
	}
	return nil
}

func validateAppPath(path string) error {
	if path == "" || len(path) > maxPathLength || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return fmt.Errorf("app path %q must be a clean absolute path", path)
	}
	if strings.ContainsAny(path, "\x00\n\r") {
		return fmt.Errorf("app path %q contains a control character", path)
	}
	return nil
}
