package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/relux-works/mac-infra/internal/maccore"
)

var callVPNCore = maccore.Call

func runVPNCore(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: mac-infra-core vpn-core install|rollback|status")
		return 2
	}
	fs := flag.NewFlagSet("vpn-core "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	req := maccore.VPNCoreRequest{Target: "vpn-core"}
	var action maccore.Action
	switch args[0] {
	case "install":
		action = maccore.ActionVPNCoreInstall
		fs.StringVar(&req.Package, "package", "", "absolute keeper-staged package directory")
		fallthrough
	case "rollback":
		if action == "" {
			action = maccore.ActionVPNCoreRollback
		}
		fs.StringVar(&req.ExpectedDigest, "expect-digest", "", "required pinned install digest (64 lowercase hex characters)")
	case "status":
		action = maccore.ActionVPNCoreStatus
	default:
		fmt.Fprintf(stderr, "unknown vpn-core command %q\n", args[0])
		return 2
	}
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "vpn-core commands take no positional arguments")
		return 2
	}
	if action != maccore.ActionVPNCoreStatus && (!isSHA256Hex(req.ExpectedDigest) || strings.ToLower(req.ExpectedDigest) != req.ExpectedDigest) {
		fmt.Fprintln(stderr, "--expect-digest is required and must be 64 lowercase hex characters")
		return 2
	}
	if action == maccore.ActionVPNCoreInstall && (!filepath.IsAbs(req.Package) || filepath.Clean(req.Package) != req.Package) {
		fmt.Fprintln(stderr, "--package must be an absolute clean directory path")
		return 2
	}
	response, err := callVPNCore(maccore.DefaultServiceConfig(), maccore.Request{Action: action, VPNCore: &req})
	if response.VPNCore != nil {
		_ = json.NewEncoder(stdout).Encode(response.VPNCore)
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", response.ErrorCode, err)
		return 1
	}
	return 0
}
