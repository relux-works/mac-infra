package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/relux-works/mac-infra/internal/maccore"
	"golang.org/x/sys/unix"
)

var callVPNCore = maccore.Call

func ownerSHA256(data []byte) string { hash := sha256.Sum256(data); return hex.EncodeToString(hash[:]) }

func writeVPNAuthorization(path string, data []byte) error {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	_, err = file.Write(data)
	if err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func runVPNCore(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: mac-infra-core vpn-core authorize|install|rollback|status")
		return 2
	}
	fs := flag.NewFlagSet("vpn-core "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	req := maccore.VPNCoreRequest{Target: "vpn-core"}
	var action maccore.Action
	var authorizationPath, signaturePath, outPath string
	switch args[0] {
	case "authorize":
		action = maccore.ActionVPNCoreAuthorize
		fs.StringVar(&req.AuthorizeAction, "action", "", "required install or rollback")
		fs.StringVar(&outPath, "out", "", "exclusive authorization output file")
	case "install":
		action = maccore.ActionVPNCoreInstall
		fs.StringVar(&req.Package, "package", "", "absolute keeper-staged package directory")
	case "rollback":
		action = maccore.ActionVPNCoreRollback
	case "status":
		action = maccore.ActionVPNCoreStatus
	default:
		fmt.Fprintf(stderr, "unknown vpn-core command %q\n", args[0])
		return 2
	}
	if action != maccore.ActionVPNCoreStatus {
		fs.StringVar(&req.ExpectedDigest, "expect-digest", "", "required 64 lowercase hex package digest")
	}
	if action == maccore.ActionVPNCoreInstall || action == maccore.ActionVPNCoreRollback {
		fs.StringVar(&authorizationPath, "authorization", "", "required authorization statement file")
		fs.StringVar(&signaturePath, "signature", "", "required DER low-S signature file")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "vpn-core commands take no positional arguments")
		return 2
	}
	if action != maccore.ActionVPNCoreStatus && (!isSHA256Hex(req.ExpectedDigest) || strings.ToLower(req.ExpectedDigest) != req.ExpectedDigest) {
		fmt.Fprintln(stderr, "invalid_digest: --expect-digest is required and must be 64 lowercase hex characters")
		return 2
	}
	if action == maccore.ActionVPNCoreAuthorize && ((req.AuthorizeAction != "install" && req.AuthorizeAction != "rollback") || outPath == "") {
		fmt.Fprintln(stderr, "invalid_request: --action install|rollback and --out FILE are required")
		return 2
	}
	if action == maccore.ActionVPNCoreInstall && (!filepath.IsAbs(req.Package) || filepath.Clean(req.Package) != req.Package) {
		fmt.Fprintln(stderr, "--package must be an absolute clean directory path")
		return 2
	}
	if action == maccore.ActionVPNCoreInstall || action == maccore.ActionVPNCoreRollback {
		if authorizationPath == "" || signaturePath == "" {
			fmt.Fprintln(stderr, "authorization_missing: --authorization and --signature are required")
			return 2
		}
		var err error
		req.Authorization, err = maccore.ReadVPNCoreInput(authorizationPath, 4096)
		if err == nil {
			req.Signature, err = maccore.ReadVPNCoreInput(signaturePath, 4096)
		}
		if err != nil {
			fmt.Fprintf(stderr, "authorization_invalid: %v\n", err)
			return 1
		}
	}
	response, err := callVPNCore(maccore.DefaultServiceConfig(), maccore.Request{Action: action, VPNCore: &req})
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", response.ErrorCode, err)
		if response.VPNCore != nil {
			_ = json.NewEncoder(stdout).Encode(response.VPNCore)
		}
		return 1
	}
	if action == maccore.ActionVPNCoreAuthorize {
		if len(response.Authorization) == 0 {
			fmt.Fprintln(stderr, "authorization_invalid: daemon returned no statement")
			return 1
		}
		if err := writeVPNAuthorization(outPath, response.Authorization); err != nil {
			fmt.Fprintf(stderr, "authorization output: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "authorization sha256: %s\ndigest: %s\n", ownerSHA256(response.Authorization), req.ExpectedDigest[:8])
	} else if response.VPNCore != nil {
		_ = json.NewEncoder(stdout).Encode(response.VPNCore)
	}
	return 0
}
