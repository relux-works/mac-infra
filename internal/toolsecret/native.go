package toolsecret

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

const WorkerArgument = "__toolsecret_metadata_worker"
const QueryTimeout = 10 * time.Second
const AuthorizationTimeout = 60 * time.Second

type nativeRequest struct {
	Operation string `json:"operation"`
	Keychain  string `json:"keychain,omitempty"`
	Path      string `json:"path,omitempty"`
	Plan      *Plan  `json:"plan,omitempty"`
	AllowUI   bool   `json:"allow_ui"`
}

type nativeResponse struct {
	Status   int    `json:"status"`
	Message  string `json:"message"`
	Items    []Item `json:"items"`
	Owner    Owner  `json:"owner"`
	Prepared *Item  `json:"prepared"`
}

// Native executes each Security.framework operation in a killable child, rather
// than leaving a goroutine blocked in cgo after a context deadline.
type Native struct{}

func (Native) call(ctx context.Context, req nativeRequest) (nativeResponse, error) {
	timeout := QueryTimeout
	if req.AllowUI {
		timeout = AuthorizationTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var r nativeResponse
	exe, err := os.Executable()
	if err != nil {
		return r, err
	}
	body, err := json.Marshal(req)
	if err != nil {
		return r, err
	}
	cmd := exec.CommandContext(ctx, exe, WorkerArgument)
	cmd.Stdin = bytes.NewReader(body)
	// The native child independently checks the original terminal descriptors.
	if req.AllowUI {
		cmd.ExtraFiles = []*os.File{os.Stdin, os.Stdout}
	}
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return r, fmt.Errorf("native %s timed out; mutation outcome may be unknown: %w", req.Operation, ctx.Err())
	}
	if err != nil {
		return r, fmt.Errorf("native %s failed: %w", req.Operation, err)
	}
	if err = json.Unmarshal(out, &r); err != nil {
		return r, fmt.Errorf("invalid metadata worker response: %w", err)
	}
	if r.Status != 0 {
		if r.Status == -4 {
			return r, refuse("spi_unavailable", r.Message)
		}
		return r, fmt.Errorf("%s: %s (OSStatus %d)", req.Operation, r.Message, r.Status)
	}
	return r, nil
}

func (n Native) Startup(ctx context.Context) error {
	_, e := n.call(ctx, nativeRequest{Operation: "startup"})
	return e
}
func (n Native) Inventory(ctx context.Context, k string) ([]Item, error) {
	r, e := n.call(ctx, nativeRequest{Operation: "inventory", Keychain: k})
	return r.Items, e
}
func (n Native) Owner(ctx context.Context, p string) (Owner, error) {
	r, e := n.call(ctx, nativeRequest{Operation: "owner", Path: p})
	return r.Owner, e
}
func (n Native) Apply(ctx context.Context, k string, p Plan, ui bool) error {
	_, e := n.call(ctx, nativeRequest{Operation: "apply", Keychain: k, Plan: &p, AllowUI: ui})
	return e
}

// Worker serves exactly one metadata request. Only the CLI calls this dispatch;
// default tests never construct Native or perform keychain I/O.
func Worker(in io.Reader, out io.Writer) int {
	body, err := io.ReadAll(io.LimitReader(in, 4<<20))
	if err != nil {
		return 1
	}
	var req nativeRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&req); err != nil {
		return 1
	}
	if decoder.Decode(new(any)) != io.EOF {
		return 1
	}
	if req.Operation != "startup" && req.Operation != "inventory" && req.Operation != "owner" && req.Operation != "apply" {
		return 1
	}
	if req.AllowUI && (req.Operation != "apply" || !terminalFD(3) || !terminalFD(4)) {
		return 3
	}
	if req.AllowUI && MultiplexerPresent(os.LookupEnv) {
		return 3
	}
	if req.Operation == "apply" {
		if req.Plan == nil || ValidateOwner(req.Plan.Owner) != nil {
			return 3
		}
		// Recompute instead of accepting an arbitrary ACL from the worker protocol.
		kept := map[string]Owner{}
		for _, o := range req.Plan.KeepOwners {
			kept[o.Path] = o
		}
		p, e := PlanBind(req.Plan.Before, req.Plan.Owner, BindOptions{Keep: req.Plan.Keep, KeepOwners: kept, OwnerDecision: req.Plan.OwnerDecision})
		if e != nil {
			return 3
		}
		a, _ := json.Marshal(p)
		b, _ := json.Marshal(req.Plan)
		if !bytes.Equal(a, b) {
			return 3
		}
	}
	result, err := nativeCall(string(body))
	if err != nil {
		return 1
	}
	_, err = io.WriteString(out, result)
	if err != nil && !errors.Is(err, io.EOF) {
		return 1
	}
	return 0
}
