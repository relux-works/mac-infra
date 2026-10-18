package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/security/firewallwatch"
)

func init() {
	if os.Getenv("FW_CLI_HELPER") != "1" {
		return
	}
	socket := ""
	for i, a := range os.Args {
		if a == "--host" && i+1 < len(os.Args) {
			socket = os.Args[i+1]
		}
	}
	if _, e := os.ReadFile("/dev/fd/3"); e != nil {
		os.Exit(11)
	}
	l, e := net.Listen("unix", socket)
	if e != nil {
		os.Exit(12)
	}
	_ = http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			return
		}
		var request struct {
			Input []string `json:"input"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			w.WriteHeader(400)
			return
		}
		data := []any{}
		for i := range request.Input {
			data = append(data, map[string]any{"index": i, "embedding": []float64{1, 0}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	os.Exit(0)
}
func fixtureBackend(t *testing.T, c firewallwatch.Config) firewallwatch.Config {
	t.Helper()
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	c.Model = filepath.Join(filepath.Dir(c.StateDir), "fake.model")
	if e = os.WriteFile(c.Model, []byte("model"), 0600); e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256([]byte("model"))
	c.ModelSHA256 = hex.EncodeToString(h[:])
	c.LlamaServer = filepath.Join(filepath.Dir(c.StateDir), "fake.server")
	script := fmt.Sprintf("#!/bin/sh\nFW_CLI_HELPER=1 exec '%s' \"$@\"\n", strings.ReplaceAll(binary, "'", "'\\''"))
	if e = os.WriteFile(c.LlamaServer, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	return c
}
