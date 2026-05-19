package loadprofile

import "time"

type CaptureCommand struct {
	Name        string
	Executable  string
	Args        []string
	Filename    string
	Optional    bool
	Timeout     time.Duration
	Description string
}

func DefaultCaptureCommands(includeLogs bool) []CaptureCommand {
	commands := []CaptureCommand{
		{
			Name:        "sw_vers",
			Executable:  "/usr/bin/sw_vers",
			Filename:    "sw_vers.txt",
			Timeout:     5 * time.Second,
			Description: "macOS version",
		},
		{
			Name:        "uname",
			Executable:  "/usr/bin/uname",
			Args:        []string{"-a"},
			Filename:    "uname.txt",
			Timeout:     5 * time.Second,
			Description: "kernel and machine identifier",
		},
		{
			Name:        "uptime",
			Executable:  "/usr/bin/uptime",
			Filename:    "uptime.txt",
			Timeout:     5 * time.Second,
			Description: "load averages and uptime",
		},
		{
			Name:        "hardware",
			Executable:  "/usr/sbin/sysctl",
			Args:        []string{"-n", "hw.ncpu", "hw.memsize", "machdep.cpu.brand_string"},
			Filename:    "hardware.txt",
			Timeout:     5 * time.Second,
			Description: "CPU count, memory size, and CPU model",
		},
		{
			Name:        "vm_stat",
			Executable:  "/usr/bin/vm_stat",
			Filename:    "vm_stat.txt",
			Timeout:     5 * time.Second,
			Description: "virtual memory counters",
		},
		{
			Name:        "memory_pressure",
			Executable:  "/usr/bin/memory_pressure",
			Args:        []string{"-Q"},
			Filename:    "memory_pressure.txt",
			Optional:    true,
			Timeout:     10 * time.Second,
			Description: "memory pressure snapshot",
		},
		{
			Name:        "iostat",
			Executable:  "/usr/sbin/iostat",
			Args:        []string{"-d", "-w", "1", "-c", "2"},
			Filename:    "iostat.txt",
			Optional:    true,
			Timeout:     10 * time.Second,
			Description: "disk IO counters",
		},
		{
			Name:        "df",
			Executable:  "/bin/df",
			Args:        []string{"-h"},
			Filename:    "df.txt",
			Optional:    true,
			Timeout:     10 * time.Second,
			Description: "filesystem capacity",
		},
		{
			Name:        "netstat_interfaces",
			Executable:  "/usr/sbin/netstat",
			Args:        []string{"-ibn"},
			Filename:    "netstat-interfaces.txt",
			Optional:    true,
			Timeout:     10 * time.Second,
			Description: "network interface counters",
		},
		{
			Name:        "netstat_routes",
			Executable:  "/usr/sbin/netstat",
			Args:        []string{"-rn"},
			Filename:    "netstat-routes.txt",
			Optional:    true,
			Timeout:     10 * time.Second,
			Description: "routing table",
		},
		{
			Name:        "top",
			Executable:  "/usr/bin/top",
			Args:        []string{"-l", "1", "-n", "40", "-stats", "pid,command,cpu,mem,threads,state,user"},
			Filename:    "top.txt",
			Optional:    true,
			Timeout:     15 * time.Second,
			Description: "top process snapshot",
		},
		{
			Name:        "ps",
			Executable:  "/bin/ps",
			Args:        PSArgs(),
			Filename:    "ps.txt",
			Timeout:     5 * time.Second,
			Description: "full process table",
		},
		{
			Name:        "pmset_assertions",
			Executable:  "/usr/bin/pmset",
			Args:        []string{"-g", "assertions"},
			Filename:    "pmset-assertions.txt",
			Optional:    true,
			Timeout:     10 * time.Second,
			Description: "power assertions",
		},
		{
			Name:        "pmset_settings",
			Executable:  "/usr/bin/pmset",
			Args:        []string{"-g"},
			Filename:    "pmset-settings.txt",
			Optional:    true,
			Timeout:     10 * time.Second,
			Description: "power management settings",
		},
		{
			Name:        "pmset_thermal",
			Executable:  "/usr/bin/pmset",
			Args:        []string{"-g", "therm"},
			Filename:    "pmset-thermal.txt",
			Optional:    true,
			Timeout:     10 * time.Second,
			Description: "thermal pressure snapshot",
		},
	}

	if includeLogs {
		commands = append(commands, CaptureCommand{
			Name:       "system_logs",
			Executable: "/usr/bin/log",
			Args: []string{
				"show",
				"--last", "20m",
				"--style", "compact",
				"--predicate", `eventMessage CONTAINS[c] "CPU" || eventMessage CONTAINS[c] "memory pressure" || eventMessage CONTAINS[c] "thermal" || eventMessage CONTAINS[c] "jetsam"`,
			},
			Filename:    "logs-load-pressure.txt",
			Optional:    true,
			Timeout:     30 * time.Second,
			Description: "recent CPU, memory pressure, thermal, and jetsam logs",
		})
	}

	return commands
}

func PSArgs() []string {
	return []string{"-axo", "pid=,ppid=,user=,%cpu=,%mem=,rss=,etime=,command="}
}
