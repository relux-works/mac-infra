package maccore

type Action string

const (
	ActionPing                   Action = "ping"
	ActionRestartAudio           Action = "restart_audio"
	ActionCleanupAnyConnect      Action = "cleanup_anyconnect"
	ActionSleepPreventionEnable  Action = "sleep_prevention_enable"
	ActionSleepPreventionDisable Action = "sleep_prevention_disable"
	ActionRestartFSEvents        Action = "restart_fsevents"
)

type Request struct {
	Action          Action `json:"action"`
	IncludeUSBAudio bool   `json:"include_usb_audio,omitempty"`
	Force           bool   `json:"force,omitempty"`
	// RSSThresholdBytes guards restart_fsevents: below it the daemon refuses
	// unless Force is set. Zero selects the package default.
	RSSThresholdBytes int64 `json:"rss_threshold_bytes,omitempty"`
}

type Response struct {
	OK        bool            `json:"ok"`
	Error     string          `json:"error,omitempty"`
	DaemonPID int             `json:"daemon_pid,omitempty"`
	Commands  []CommandResult `json:"commands,omitempty"`
}

type CommandResult struct {
	Command string `json:"command"`
	Output  string `json:"output,omitempty"`
}
