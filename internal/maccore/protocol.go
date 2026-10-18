package maccore

import "github.com/relux-works/mac-infra/internal/security/firewall"

type Action string

const (
	ActionPing                   Action = "ping"
	ActionVPNCoreAuthorize       Action = "vpn_core_authorize"
	ActionVPNCoreInstall         Action = "vpn_core_install"
	ActionVPNCoreRollback        Action = "vpn_core_rollback"
	ActionVPNCoreStatus          Action = "vpn_core_status"
	ActionRestartAudio           Action = "restart_audio"
	ActionCleanupAnyConnect      Action = "cleanup_anyconnect"
	ActionSleepPreventionEnable  Action = "sleep_prevention_enable"
	ActionSleepPreventionDisable Action = "sleep_prevention_disable"
	ActionRestartFSEvents        Action = "restart_fsevents"
	ActionFirewallStatus         Action = "firewall_status"
	ActionFirewallPlan           Action = "firewall_plan"
	ActionFirewallApply          Action = "firewall_apply"
)

type Request struct {
	VPNCore         *VPNCoreRequest `json:"vpn_core,omitempty"`
	Action          Action          `json:"action"`
	IncludeUSBAudio bool            `json:"include_usb_audio,omitempty"`
	Force           bool            `json:"force,omitempty"`
	// RSSThresholdBytes guards restart_fsevents: below it the daemon refuses
	// unless Force is set. Zero selects the package default.
	RSSThresholdBytes int64 `json:"rss_threshold_bytes,omitempty"`
	// Firewall carries the desired state for firewall_plan and
	// firewall_apply; the daemon validates it again.
	Firewall *firewall.Config `json:"firewall,omitempty"`
}

type Response struct {
	Authorization []byte           `json:"authorization,omitempty"`
	ErrorCode     string           `json:"error_code,omitempty"`
	VPNCore       *VPNCoreStatus   `json:"vpn_core,omitempty"`
	OK            bool             `json:"ok"`
	Error         string           `json:"error,omitempty"`
	DaemonPID     int              `json:"daemon_pid,omitempty"`
	Commands      []CommandResult  `json:"commands,omitempty"`
	Firewall      *firewall.Report `json:"firewall,omitempty"`
}

type CommandResult struct {
	Command string `json:"command"`
	Output  string `json:"output,omitempty"`
}
