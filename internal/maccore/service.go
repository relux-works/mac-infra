package maccore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/relux-works/mac-infra/internal/anyconnect"
)

const commandTimeout = 10 * time.Second

var execCommandContextCore = exec.CommandContext
var execCommandCore = exec.Command

func Available(cfg ServiceConfig) bool {
	status, err := InspectService(cfg)
	return err == nil && status.Reachable
}

func InspectService(cfg ServiceConfig) (ServiceStatus, error) {
	status := ServiceStatus{
		Label:      cfg.Label,
		PlistPath:  cfg.PlistPath,
		SocketPath: cfg.SocketPath,
	}
	resp, err := Call(cfg, Request{Action: ActionPing})
	if err != nil {
		if isUnavailable(err) {
			return status, nil
		}
		return status, err
	}
	status.Reachable = resp.OK
	status.DaemonPID = resp.DaemonPID
	return status, nil
}

func Call(cfg ServiceConfig, request Request) (Response, error) {
	conn, err := net.DialTimeout("unix", cfg.SocketPath, 2*time.Second)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return Response{}, err
	}
	var response Response
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return Response{}, err
	}
	if !response.OK {
		if response.Error == "" {
			response.Error = "mac-infra-core request failed"
		}
		return response, errors.New(response.Error)
	}
	return response, nil
}

func RestartAudio(cfg ServiceConfig, includeUSBAudio bool) (Response, error) {
	return Call(cfg, Request{
		Action:          ActionRestartAudio,
		IncludeUSBAudio: includeUSBAudio,
	})
}

func CleanupAnyConnect(cfg ServiceConfig, force bool) (Response, error) {
	return Call(cfg, Request{
		Action: ActionCleanupAnyConnect,
		Force:  force,
	})
}

func EnableSleepPrevention(cfg ServiceConfig) (Response, error) {
	return Call(cfg, Request{Action: ActionSleepPreventionEnable})
}

func DisableSleepPrevention(cfg ServiceConfig) (Response, error) {
	return Call(cfg, Request{Action: ActionSleepPreventionDisable})
}

func RequestSudoCredentials() error {
	return ensureSudoCredentials()
}

func InstallService(cfg ServiceConfig, binaryPath string, clientUID, clientGID int) error {
	if err := ensureSudoCredentials(); err != nil {
		return fmt.Errorf("sudo authentication: %w", err)
	}

	plistData := RenderServicePlist(cfg, binaryPath, clientUID, clientGID)
	tmpFile, err := os.CreateTemp("", "mac-infra-core-*.plist")
	if err != nil {
		return fmt.Errorf("create temp plist: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(plistData); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp plist: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp plist: %w", err)
	}

	if _, err := runPrivilegedCommand("install", "-o", "root", "-g", "wheel", "-m", "0644", tmpPath, cfg.PlistPath); err != nil {
		return fmt.Errorf("install plist: %w", err)
	}
	_, _ = runPrivilegedCommand("launchctl", "bootout", launchctlTarget(cfg.Label))
	if _, err := runPrivilegedCommand("launchctl", "bootstrap", "system", cfg.PlistPath); err != nil {
		return fmt.Errorf("bootstrap service: %w", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		status, err := InspectService(cfg)
		if err != nil {
			return err
		}
		if status.Reachable {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("service did not become reachable at %s", cfg.SocketPath)
}

func UninstallService(cfg ServiceConfig) error {
	if err := ensureSudoCredentials(); err != nil {
		return fmt.Errorf("sudo authentication: %w", err)
	}
	_, _ = runPrivilegedCommand("launchctl", "bootout", launchctlTarget(cfg.Label))
	_, _ = runPrivilegedCommand("rm", "-f", cfg.PlistPath, cfg.SocketPath)
	return nil
}

func RunDaemon(cfg ServiceConfig, clientUID, clientGID int) error {
	daemon := serviceDaemon{
		cfg:       cfg,
		clientUID: clientUID,
		clientGID: clientGID,
	}
	return daemon.serve()
}

type serviceDaemon struct {
	cfg       ServiceConfig
	clientUID int
	clientGID int
}

func (d serviceDaemon) serve() error {
	if err := os.MkdirAll(filepath.Dir(d.cfg.SocketPath), 0o755); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}
	_ = os.Remove(d.cfg.SocketPath)

	listener, err := net.Listen("unix", d.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("listen on socket: %w", err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(d.cfg.SocketPath)
	}()

	if err := os.Chmod(d.cfg.SocketPath, 0o600); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(d.cfg.SocketPath, d.clientUID, d.clientGID); err != nil {
			return fmt.Errorf("chown socket: %w", err)
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	errCh := make(chan error, 1)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				errCh <- err
				return
			}
			go d.handleConn(conn)
		}
	}()

	select {
	case <-sigCh:
		return nil
	case err := <-errCh:
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}

func (d serviceDaemon) handleConn(conn net.Conn) {
	defer conn.Close()

	var request Request
	if err := json.NewDecoder(conn).Decode(&request); err != nil {
		_ = json.NewEncoder(conn).Encode(Response{Error: err.Error()})
		return
	}

	response := Response{OK: true, DaemonPID: os.Getpid()}
	switch request.Action {
	case ActionPing:
	case ActionRestartAudio:
		results, err := restartAudioDaemons(request.IncludeUSBAudio)
		response.Commands = results
		if err != nil {
			response.OK = false
			response.Error = err.Error()
		}
	case ActionCleanupAnyConnect:
		results, err := cleanupAnyConnect(request.Force)
		response.Commands = results
		if err != nil {
			response.OK = false
			response.Error = err.Error()
		}
	case ActionSleepPreventionEnable, ActionSleepPreventionDisable:
		results, err := applySleepPrevention(request.Action)
		response.Commands = results
		if err != nil {
			response.OK = false
			response.Error = err.Error()
		}
	case ActionRestartFSEvents:
		results, err := restartFSEvents(request.Force, request.RSSThresholdBytes)
		response.Commands = results
		if err != nil {
			response.OK = false
			response.Error = err.Error()
		}
	default:
		response.OK = false
		response.Error = fmt.Sprintf("unsupported mac-infra-core action %q", request.Action)
	}

	_ = json.NewEncoder(conn).Encode(response)
}

func restartAudioDaemons(includeUSBAudio bool) ([]CommandResult, error) {
	commands := []struct {
		name     string
		args     []string
		optional bool
	}{
		{name: "/usr/bin/killall", args: []string{"coreaudiod"}},
	}
	if includeUSBAudio {
		commands = append(commands, struct {
			name     string
			args     []string
			optional bool
		}{name: "/usr/bin/killall", args: []string{"usbaudiod"}, optional: true})
	}

	var results []CommandResult
	for _, item := range commands {
		ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
		cmd := execCommandContextCore(ctx, item.name, item.args...)
		out, err := cmd.CombinedOutput()
		cancel()
		result := CommandResult{
			Command: strings.Join(append([]string{item.name}, item.args...), " "),
			Output:  strings.TrimSpace(string(out)),
		}
		results = append(results, result)
		if err != nil {
			if item.optional {
				continue
			}
			if ctx.Err() == context.DeadlineExceeded {
				return results, fmt.Errorf("%s timed out after %s", result.Command, commandTimeout)
			}
			if result.Output != "" {
				return results, fmt.Errorf("%s: %w (%s)", result.Command, err, result.Output)
			}
			return results, fmt.Errorf("%s: %w", result.Command, err)
		}
	}
	return results, nil
}

func cleanupAnyConnect(force bool) ([]CommandResult, error) {
	var results []CommandResult
	if !force {
		result, state, err := verifyAnyConnectDisconnected()
		results = append(results, result)
		if err != nil {
			return results, err
		}
		if state != anyconnect.VPNStateDisconnected {
			return results, fmt.Errorf("refusing AnyConnect cleanup while vpn state is %q; disconnect first or pass --force", state)
		}
	}

	for _, item := range []struct {
		name          string
		args          []string
		optionalNoOp  bool
		noOpExitCodes map[int]bool
	}{
		{
			name:         "/usr/bin/pkill",
			args:         []string{"-TERM", "-f", "com[.]cisco[.]anyconnect[.]macos[.]acsockext"},
			optionalNoOp: true,
			noOpExitCodes: map[int]bool{
				1: true,
			},
		},
		{
			name: "/bin/launchctl",
			args: []string{"kickstart", "-k", "system/" + anyconnect.VPNAgentLabel},
		},
	} {
		result, err := runCoreCommand(item.name, item.args...)
		results = append(results, result)
		if err != nil {
			if item.optionalNoOp && item.noOpExitCodes[exitCode(err)] {
				continue
			}
			return results, err
		}
	}
	return results, nil
}

func verifyAnyConnectDisconnected() (CommandResult, anyconnect.VPNState, error) {
	result, err := runCoreCommand("/opt/cisco/anyconnect/bin/vpn", "status")
	state := anyconnect.ParseVPNState(result.Output)
	if err != nil {
		return result, state, fmt.Errorf("verify AnyConnect status: %w", err)
	}
	if state == anyconnect.VPNStateUnknown {
		return result, state, fmt.Errorf("could not determine AnyConnect state from vpn status output")
	}
	return result, state, nil
}

func runCoreCommand(name string, args ...string) (CommandResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := execCommandContextCore(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	result := CommandResult{
		Command: strings.Join(append([]string{name}, args...), " "),
		Output:  strings.TrimSpace(string(out)),
	}
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return result, fmt.Errorf("%s timed out after %s", result.Command, commandTimeout)
		}
		if result.Output != "" {
			return result, fmt.Errorf("%s: %w (%s)", result.Command, err, result.Output)
		}
		return result, fmt.Errorf("%s: %w", result.Command, err)
	}
	return result, nil
}

func exitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func RenderServicePlist(cfg ServiceConfig, binaryPath string, clientUID, clientGID int) []byte {
	var builder strings.Builder
	builder.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	builder.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	builder.WriteString(`<plist version="1.0">` + "\n")
	builder.WriteString(`<dict>` + "\n")
	builder.WriteString(`  <key>Label</key>` + "\n")
	builder.WriteString(`  <string>` + plistEscape(cfg.Label) + `</string>` + "\n")
	builder.WriteString(`  <key>ProgramArguments</key>` + "\n")
	builder.WriteString(`  <array>` + "\n")
	for _, value := range []string{
		binaryPath,
		"_daemon",
		"--socket",
		cfg.SocketPath,
		"--client-uid",
		strconv.Itoa(clientUID),
		"--client-gid",
		strconv.Itoa(clientGID),
	} {
		builder.WriteString(`    <string>` + plistEscape(value) + `</string>` + "\n")
	}
	builder.WriteString(`  </array>` + "\n")
	builder.WriteString(`  <key>RunAtLoad</key>` + "\n")
	builder.WriteString(`  <true/>` + "\n")
	builder.WriteString(`  <key>KeepAlive</key>` + "\n")
	builder.WriteString(`  <true/>` + "\n")
	builder.WriteString(`</dict>` + "\n")
	builder.WriteString(`</plist>` + "\n")
	return []byte(builder.String())
}

func ensureSudoCredentials() error {
	if os.Geteuid() == 0 {
		return nil
	}

	cmd := execCommandCore("sudo", "-n", "true")
	if err := cmd.Run(); err == nil {
		return nil
	}

	if !stdinSupportsPrompt() {
		return fmt.Errorf("sudo credentials are not cached; run `sudo -v` in an interactive shell and retry")
	}

	cmd = execCommandCore("sudo", "-v")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func stdinSupportsPrompt() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func runPrivilegedCommand(name string, args ...string) ([]byte, error) {
	if os.Geteuid() == 0 {
		return runCommand(name, args...)
	}
	return runCommand("sudo", append([]string{name}, args...)...)
}

func runCommand(name string, args ...string) ([]byte, error) {
	out, err := execCommandCore(name, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func launchctlTarget(label string) string {
	return "system/" + label
}

func plistEscape(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return replacer.Replace(value)
}

func isUnavailable(err error) bool {
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return true
	}
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED)
}
