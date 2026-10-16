package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const maxCommandOutput = 1 << 20

// ExecRunner runs only the fixed vocabulary in allowedArgv, without a shell,
// with a deadline and bounded combined output.
type ExecRunner struct {
	Timeout time.Duration
}

func (r ExecRunner) Run(ctx context.Context, path string, args ...string) ([]byte, error) {
	if !allowedArgv(path, args) {
		return nil, fmt.Errorf("command not allowed: %s", path)
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var out boundedBuffer
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if ctx.Err() != nil {
		return out.Bytes(), ctx.Err()
	}
	if out.exceeded {
		return nil, errors.New("command output limit reached")
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return out.Bytes(), &ExitError{Code: exit.ExitCode()}
	}
	return out.Bytes(), err
}

type boundedBuffer struct {
	bytes.Buffer
	exceeded bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if room := maxCommandOutput - b.Len(); len(p) > room {
		b.exceeded = true
		p = p[:max(room, 0)]
	}
	b.Buffer.Write(p)
	return len(p), nil
}

var socketFilterArity = map[string]int{
	"--getglobalstate": 0, "--getblockall": 0, "--getstealthmode": 0, "--getallowsigned": 0, "--listapps": 0,
	"--setglobalstate": 1, "--setblockall": 1, "--setstealthmode": 1, "--setallowsigned": 1, "--setallowsignedapp": 1,
	"--add": 1, "--remove": 1, "--blockapp": 1, "--unblockapp": 1,
}

// allowedArgv is the last line of defence: even a planner bug cannot turn
// the root helper into a general command runner. Notably there is no way to
// pass "--setglobalstate off".
func allowedArgv(path string, args []string) bool {
	switch path {
	case SocketFilterFW:
		if len(args) == 0 {
			return false
		}
		arity, ok := socketFilterArity[args[0]]
		if !ok || len(args) != 1+arity {
			return false
		}
		if arity == 0 {
			return true
		}
		switch args[0] {
		case "--setglobalstate":
			return args[1] == "on"
		case "--setblockall", "--setstealthmode", "--setallowsigned", "--setallowsignedapp":
			return args[1] == "on" || args[1] == "off"
		}
		return validateAppPath(args[1]) == nil
	case Launchctl:
		if len(args) == 2 && args[0] == "print-disabled" && args[1] == "system" {
			return true
		}
		if len(args) == 2 && (args[0] == "print" || args[0] == "disable" || args[0] == "enable" || args[0] == "bootout") {
			for _, spec := range serviceAllowlist {
				if args[1] == "system/"+spec.Label {
					return true
				}
			}
			return false
		}
		if len(args) == 3 && args[0] == "bootstrap" && args[1] == "system" {
			for _, spec := range serviceAllowlist {
				if args[2] == spec.PlistPath {
					return true
				}
			}
		}
		return false
	case Codesign:
		if len(args) == 3 && args[0] == "--verify" && args[1] == "-R=anchor apple generic" {
			return validateAppPath(args[2]) == nil
		}
		return len(args) == 3 && args[0] == "-d" && args[1] == "-v" && validateAppPath(args[2]) == nil
	case Plutil:
		return len(args) == 6 && strings.Join(args[:5], " ") == "-extract CFBundleIdentifier raw -o -" &&
			validateAppPath(args[5]) == nil && strings.HasSuffix(args[5], filepath.Join(".app", "Contents", "Info.plist"))
	case Lsof:
		return strings.Join(args, " ") == strings.Join(lsofListenerArgs, " ")
	}
	return false
}
