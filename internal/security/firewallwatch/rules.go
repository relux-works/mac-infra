package firewallwatch

import "strings"

// Rules preserves benchmark ordering after the mandatory hard rules.
func Rules(it Item) (decision Decision, fired bool) {
	if it.Spike {
		return Decision{Label: "decide", Reason: "hard_deny_spike"}, true
	}
	if it.Verdict != "allow" && it.Verdict != "observed" {
		return Decision{Label: "decide", Reason: "hard_non_allow"}, true
	}
	signer := strings.ToLower(it.Signer)
	// ALF only evaluates inbound acceptance, so its flows count as inbound even though
	// the log line carries no direction (Kind stays "unknown").
	inboundSide := it.Kind == "inbound" || it.Source == "alf"
	if inboundSide && it.Verdict == "allow" && (strings.Contains(signer, "unsigned") || strings.Contains(signer, "ad-hoc") || strings.Contains(signer, "no designated requirement")) {
		return Decision{Label: "decide", Reason: "hard_unsigned_inbound"}, true
	}
	if it.Source == "alf" && it.Verdict == "allow" && (signer == "unknown" || signer == "") {
		return Decision{Label: "decide", Reason: "hard_unverified_inbound"}, true
	}
	app := strings.ToLower(it.App)
	base := app[strings.LastIndex(app, "/")+1:]
	has := func(xs ...string) bool {
		for _, x := range xs {
			if strings.Contains(app, x) {
				return true
			}
		}
		return false
	}
	exposed := it.Remote == "lan" || strings.HasPrefix(it.Remote, "internet")
	interp := false
	for _, x := range []string{"python3", "python", "ruby", "perl", "node", "php", "java", "bash", "sh", "zsh", "nc"} {
		if base == x || strings.HasPrefix(base, x+" ") || versionedInterpreter(base, x) {
			interp = true
		}
	}
	userPath := strings.HasPrefix(app, "/private/tmp") || strings.HasPrefix(app, "/tmp") ||
		strings.Contains(app, "/downloads/") || strings.Contains(app, "/.") || strings.Contains(app, "application support/.")
	switch {
	case userPath:
		return Decision{Label: "decide", Reason: "policy_user_path"}, true
	case it.Remote == "internet-raw-ip":
		return Decision{Label: "decide", Reason: "policy_raw_ip"}, true
	case it.MBOut >= 1000 && it.Count <= 3:
		return Decision{Label: "decide", Reason: "policy_upload_spike"}, true
	case it.Kind == "inbound" && exposed && (interp || has("sshd", "screensharingd", "smbd", "anydesk", "teamviewer", "vnc", "rustdesk")):
		return Decision{Label: "decide", Reason: "policy_exposed_service"}, true
	case it.Kind == "inbound" && it.Remote == "internet" && has("torrent", "transmission", "deluge"):
		return Decision{Label: "decide", Reason: "policy_torrent"}, true
	case it.Kind == "outbound" && it.Signer == "Apple" && has("calculator.app", "textedit.app", "preview.app", "chess.app", "stickies.app"):
		return Decision{Label: "decide", Reason: "policy_non_network_app"}, true
	case it.Source == SourceNetfilter && it.Kind == "outbound" && strings.HasPrefix(it.Remote, "internet") && (signer == "unsigned" || signer == "ad-hoc"):
		return Decision{Label: "decide", Reason: "policy_unsigned_outbound"}, true
	case it.RemotePort != nil && map[int]bool{4444: true, 6667: true, 1337: true, 31337: true, 9001: true, 9050: true}[*it.RemotePort]:
		return Decision{Label: "decide", Reason: "policy_unusual_port"}, true
	case it.Signer == "Apple" && (strings.HasPrefix(app, "/system/") || strings.HasPrefix(app, "/usr/libexec/") || strings.HasPrefix(app, "/usr/sbin/") || strings.HasPrefix(app, "com.apple.")):
		if it.Kind == "inbound" && it.Remote == "lan" {
			return Decision{Label: "noise", Reason: "policy_apple_lan"}, true
		}
		if it.Kind == "outbound" && it.RemotePort != nil && map[int]bool{443: true, 80: true, 53: true, 123: true, 5223: true}[*it.RemotePort] {
			return Decision{Label: "noise", Reason: "policy_apple_outbound"}, true
		}
	}
	return Decision{}, false
}

func versionedInterpreter(base, x string) bool {
	if !strings.HasPrefix(base, x) {
		return false
	}
	rest := strings.TrimPrefix(base, x)
	if rest == "" {
		return false
	}
	for _, r := range rest {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}
