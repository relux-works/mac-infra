package firewall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeHost simulates socketfilterfw and launchctl with their real output
// formats. Mutating commands change the state; failArgv makes one exact
// command fail, ignoreArgv makes one exit 0 without effect.
type fakeHost struct {
	state      State
	failArgv   map[string]bool
	ignoreArgv map[string]bool
	commands   []string
}

func newFakeHost(state State) *fakeHost {
	return &fakeHost{state: state, failArgv: map[string]bool{}, ignoreArgv: map[string]bool{}}
}

func (h *fakeHost) Run(_ context.Context, path string, args ...string) ([]byte, error) {
	if !allowedArgv(path, args) {
		return nil, fmt.Errorf("fake host: argv outside the allowlist: %s %v", path, args)
	}
	key := strings.Join(append([]string{path}, args...), " ")
	h.commands = append(h.commands, key)
	if h.failArgv[key] {
		return []byte("injected failure"), &ExitError{Code: 1}
	}
	if h.ignoreArgv[key] {
		return nil, nil
	}
	s := &h.state
	switch path {
	case SocketFilterFW:
		switch args[0] {
		case "--getglobalstate":
			code := 0
			if s.Enabled {
				code = 1
				if s.BlockAll {
					code = 2
				}
			}
			word := map[bool]string{false: "disabled", true: "enabled"}[s.Enabled]
			return []byte(fmt.Sprintf("Firewall is %s. (State = %d) \n", word, code)), nil
		case "--getblockall":
			return []byte(fmt.Sprintf("Firewall has block all state set to %s.\n  \n", map[bool]string{false: "disabled", true: "enabled"}[s.BlockAll])), nil
		case "--getstealthmode":
			return []byte(fmt.Sprintf("Firewall stealth mode is %s \n", onOff(s.Stealth))), nil
		case "--getallowsigned":
			en := map[bool]string{false: "DISABLED", true: "ENABLED"}
			return []byte(fmt.Sprintf("Automatically allow built-in signed software %s.\nAutomatically allow downloaded signed software %s.\n", en[s.AllowSignedBuiltin], en[s.AllowSignedDownloaded])), nil
		case "--listapps":
			return []byte(renderListApps(s.Apps)), nil
		case "--setglobalstate":
			s.Enabled = true
		case "--setblockall":
			s.BlockAll = args[1] == "on"
		case "--setstealthmode":
			s.Stealth = args[1] == "on"
		case "--setallowsigned":
			s.AllowSignedBuiltin = args[1] == "on"
		case "--setallowsignedapp":
			s.AllowSignedDownloaded = args[1] == "on"
		case "--add":
			if h.findApp(args[1]) < 0 {
				s.Apps = append(s.Apps, App{Name: args[1], Allowed: true})
			}
		case "--remove":
			if i := h.findApp(args[1]); i >= 0 {
				s.Apps = append(s.Apps[:i:i], s.Apps[i+1:]...)
			}
		case "--blockapp", "--unblockapp":
			if i := h.findApp(args[1]); i >= 0 {
				s.Apps[i].Allowed = args[0] == "--unblockapp"
			}
		}
		return []byte("ok\n"), nil
	case Launchctl:
		label := strings.TrimPrefix(args[len(args)-1], "system/")
		for i := range s.Services {
			service := &s.Services[i]
			if args[0] == "bootstrap" && args[2] != "" {
				spec, _ := LookupService(service.Name)
				if spec.PlistPath == args[2] {
					service.Loaded = true
				}
				continue
			}
			if service.Label != label {
				continue
			}
			switch args[0] {
			case "print":
				if !service.Loaded {
					return []byte(fmt.Sprintf("Bad request.\nCould not find service %q in domain for system\n", label)), &ExitError{Code: 113}
				}
				return []byte("system/" + label + " = {\n}\n"), nil
			case "disable":
				service.Disabled = true
			case "enable":
				service.Disabled = false
			case "bootout":
				service.Loaded = false
			}
		}
		if args[0] == "print-disabled" {
			var b strings.Builder
			b.WriteString("disabled services = {\n\t\t\"com.apple.xcsd.worker\" => disabled\n")
			for _, service := range s.Services {
				b.WriteString(fmt.Sprintf("\t\t%q => %s\n", service.Label, map[bool]string{false: "enabled", true: "disabled"}[service.Disabled]))
			}
			b.WriteString("\t}\n\nlogin item associations = {\n}\n")
			return []byte(b.String()), nil
		}
		return nil, nil
	}
	return nil, fmt.Errorf("fake host: unsupported %s", path)
}

func (h *fakeHost) findApp(name string) int {
	for i, app := range h.state.Apps {
		if app.Name == name {
			return i
		}
	}
	return -1
}

func (h *fakeHost) mutations() []string {
	var result []string
	for _, command := range h.commands {
		if !isReadOnlyCommand(command) {
			result = append(result, command)
		}
	}
	return result
}

func isReadOnlyCommand(command string) bool {
	for _, prefix := range []string{
		SocketFilterFW + " --get", SocketFilterFW + " --listapps",
		Launchctl + " print ", Launchctl + " print-disabled ",
	} {
		if strings.HasPrefix(command, prefix) {
			return true
		}
	}
	return false
}

func renderListApps(apps []App) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Total number of apps = %d \n", len(apps))
	for i, app := range apps {
		policy := "Allow"
		if !app.Allowed {
			policy = "Block"
		}
		fmt.Fprintf(&b, "%d : %s \n             (%s incoming connections)\n", i+1, app.Name, policy)
	}
	return b.String()
}

type fakeResolver struct {
	bundleIDs map[string]string
	signed    map[string]AppIdentity
}

func (r fakeResolver) Aliases(_ context.Context, path string) ([]string, error) {
	if id, ok := r.bundleIDs[path]; ok {
		return []string{path, id}, nil
	}
	return []string{path}, nil
}

func (r fakeResolver) VerifySigned(_ context.Context, path string) (AppIdentity, error) {
	if identity, ok := r.signed[path]; ok {
		return identity, nil
	}
	return AppIdentity{}, errors.New("code object is not signed at all")
}

// hostLikeState mirrors this host on 2026-10-17: firewall off, signed
// software auto-allowed, stock Apache loaded with an enabled override.
func hostLikeState() State {
	return State{
		AllowSignedBuiltin:    true,
		AllowSignedDownloaded: true,
		Apps:                  []App{{Name: "/usr/sbin/cupsd", Allowed: true}, {Name: "com.spotify.client", Allowed: true}},
		Services:              []Service{{Name: "apache", Label: "org.apache.httpd", Loaded: true, Disabled: false}},
	}
}

func makeApp(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func ptr(value bool) *bool { return &value }
