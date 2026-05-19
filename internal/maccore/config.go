package maccore

const (
	defaultServiceLabel      = "works.relux.mac-infra-core"
	defaultServicePlistPath  = "/Library/LaunchDaemons/works.relux.mac-infra-core.plist"
	defaultServiceSocketPath = "/var/run/works.relux.mac-infra-core.sock"
)

type ServiceConfig struct {
	Label      string
	PlistPath  string
	SocketPath string
}

type ServiceStatus struct {
	Label      string
	PlistPath  string
	SocketPath string
	Reachable  bool
	DaemonPID  int
}

func DefaultServiceConfig() ServiceConfig {
	return ServiceConfig{
		Label:      defaultServiceLabel,
		PlistPath:  defaultServicePlistPath,
		SocketPath: defaultServiceSocketPath,
	}
}
