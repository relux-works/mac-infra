package maccore

const (
	defaultServiceLabel      = "works.relux.mac-infra-core"
	defaultServicePlistPath  = "/Library/LaunchDaemons/works.relux.mac-infra-core.plist"
	defaultServiceDirectory  = "/Library/PrivilegedHelperTools/works.relux.mac-infra"
	defaultServiceBinaryPath = defaultServiceDirectory + "/mac-infra-core"
	defaultServiceSocketPath = defaultServiceDirectory + "/core.sock"
)

type ServiceConfig struct {
	OwnerKeyPath string
	Label        string
	PlistPath    string
	SocketPath   string
}

type ServiceStatus struct {
	OwnerKeyPinned bool
	OwnerKeySHA256 string
	Label          string
	PlistPath      string
	SocketPath     string
	Reachable      bool
	DaemonPID      int
}

func DefaultServiceConfig() ServiceConfig {
	return ServiceConfig{
		OwnerKeyPath: defaultServiceDirectory + "/owner-presence.spki",
		Label:        defaultServiceLabel,
		PlistPath:    defaultServicePlistPath,
		SocketPath:   defaultServiceSocketPath,
	}
}
