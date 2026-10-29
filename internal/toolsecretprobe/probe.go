// Package toolsecretprobe is the deliberately separate negative-read executable
// boundary. The metadata tool must never import this package.
package toolsecretprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

const WorkerArgument = "__toolsecret_probe_worker"

type Request struct {
	Keychain string `json:"keychain"`
	Service  string `json:"service"`
	Account  string `json:"account"`
}

// Verdict never treats missing items, malformed queries or unexpected statuses
// as proof of access denial.
func Verdict(status int) (string, error) {
	switch status {
	case 0:
		return "allowed", nil
	case -25293, -25308:
		return "refused", nil
	default:
		return "inconclusive", fmt.Errorf("probe inconclusive (OSStatus %d)", status)
	}
}
func Attempt(ctx context.Context, r Request) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	exe, err := os.Executable()
	if err != nil {
		return "inconclusive", err
	}
	b, _ := json.Marshal(r)
	cmd := exec.CommandContext(ctx, exe, WorkerArgument)
	cmd.Stdin = bytes.NewReader(b)
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return "inconclusive", fmt.Errorf("probe timed out")
	}
	if err != nil {
		return "inconclusive", fmt.Errorf("probe worker failed")
	}
	s, err := strconv.Atoi(string(out))
	if err != nil {
		return "inconclusive", fmt.Errorf("invalid probe response")
	}
	return Verdict(s)
}
func Worker(in io.Reader, out io.Writer) int {
	var r Request
	decoder := json.NewDecoder(io.LimitReader(in, 1<<20))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&r) != nil || r.Service == "" || r.Account == "" || !filepath.IsAbs(r.Keychain) {
		return 2
	}
	if decoder.Decode(new(any)) != io.EOF {
		return 2
	}
	s, err := nativeAttempt(r)
	if err != nil {
		return 1
	}
	if _, err = fmt.Fprint(out, s); err != nil {
		return 1
	}
	return 0
}
func Run(ctx context.Context, args []string, out, errout io.Writer, attempt func(context.Context, Request) (string, error)) int {
	jsonMode := false
	var rest []string
	for _, a := range args {
		if a == "--json" {
			jsonMode = true
		} else {
			rest = append(rest, a)
		}
	}
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var r Request
	fs.StringVar(&r.Keychain, "keychain", "", "explicit keychain file")
	fs.StringVar(&r.Service, "service", "", "service")
	fs.StringVar(&r.Account, "account", "", "account")
	err := fs.Parse(rest)
	exit := 1
	if err != nil || fs.NArg() != 0 || !filepath.IsAbs(r.Keychain) || r.Service == "" || r.Account == "" {
		err = fmt.Errorf("probe requires --keychain /PATH --service S --account A")
		exit = 2
	}
	result := ""
	if err == nil {
		result, err = attempt(ctx, r)
	}
	if err == nil && result != "allowed" && result != "refused" {
		err = fmt.Errorf("probe inconclusive")
	}
	if err != nil {
		result = "inconclusive"
	} else if result == "allowed" {
		err = fmt.Errorf("non-owner read was allowed")
	}
	passed := result == "refused" && err == nil
	if jsonMode {
		response := map[string]any{"ok": passed, "command": "probe", "result": result}
		if !passed {
			code := "probe_inconclusive"
			if result == "allowed" {
				code = "probe_allowed"
			}
			if exit == 2 {
				code = "usage"
			}
			response["error"] = map[string]string{"code": code, "message": err.Error(), "hint": "only refused passes; locked, missing and timed-out items are inconclusive"}
		}
		if json.NewEncoder(out).Encode(response) != nil {
			return 1
		}
	} else {
		fmt.Fprintln(out, result)
		if err != nil {
			fmt.Fprintln(errout, err)
		}
	}
	if !passed {
		return exit
	}
	return 0
}
