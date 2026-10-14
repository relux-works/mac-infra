package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/relux-works/mac-infra/internal/keyvault"
)

type sshRepeated []string

func (s *sshRepeated) String() string         { return strings.Join(*s, ",") }
func (s *sshRepeated) Set(value string) error { *s = append(*s, value); return nil }

func runSSHAgent(args []string, out output) int {
	fs := flag.NewFlagSet("ssh-agent", flag.ContinueOnError)
	socket := fs.String("socket", "", "absolute Unix socket in an owned 0700 directory")
	var keys, hookArgs sshRepeated
	fs.Var(&keys, "key", "explicit service/purpose@VERSION (repeatable)")
	hookPath := fs.String("confirm-exec", "", "absolute confirmation executable; exit 0 grants each use")
	fs.Var(&hookArgs, "confirm-arg", "literal confirmation argument (repeatable)")
	hookTimeout := fs.Duration("confirm-timeout", 15*time.Second, "confirmation deadline (at most 1m)")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return out.fail(err)
	}
	if len(positional) != 0 || *socket == "" || len(keys) == 0 || len(keys) > 32 {
		return out.fail(usagef("ssh-agent requires --socket PATH and 1..32 --key service/purpose@VERSION, with no positional arguments"))
	}
	addresses := make([]keyvault.Address, 0, len(keys))
	for _, input := range keys {
		name, ver, ok := strings.Cut(input, "@")
		version, parseErr := strconv.Atoi(ver)
		if !ok || parseErr != nil || version < 1 {
			return out.fail(usagef("--key requires service/purpose@VERSION with an explicit positive version"))
		}
		addr, err := keyvault.ParseAddress(name, keyvault.KindKey, version)
		if err != nil {
			return out.fail(err)
		}
		addresses = append(addresses, addr)
	}
	var hook func(context.Context, keyvault.SSHConfirmation) error
	if *hookPath != "" {
		hook, err = keyvault.SSHConfirmHook(*hookPath, hookArgs, *hookTimeout)
		if err != nil {
			return out.fail(usagef("%s", err))
		}
	} else if len(hookArgs) != 0 || *hookTimeout != 15*time.Second {
		return out.fail(usagef("confirmation options require --confirm-exec"))
	}
	manager, err := newManager()
	if err != nil {
		return out.fail(errors.New("SSH keyvault unavailable"))
	}
	agent, err := keyvault.NewSSHAgent(manager, addresses, hook)
	if err != nil {
		classified := keyvault.ClassifyError(err)
		return out.fail(&keyvault.Refusal{Code: classified.Code, Failure: classified.Failure, Status: classified.Status, Message: "SSH identities unavailable or signing policy refused", Hint: "use describe to inspect the selected records"})
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	listener, cleanup, err := keyvault.ListenSSH(*socket)
	if err != nil {
		return out.fail(err)
	}
	defer cleanup()
	// Readiness is public metadata. Protocol traffic only uses the socket.
	if out.json {
		out.success(map[string]any{"socket": *socket, "identities": len(addresses)}, nil)
	} else {
		fmt.Fprintf(out.stderr, "SSH agent listening on %s\n", *socket)
	}
	if err := agent.Serve(ctx, listener); err != nil {
		return out.fail(err)
	}
	return exitOK
}
