package videoprofile

import (
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/relux-works/mac-infra/internal/loadprofile"
)

const DefaultArtifactRoot = ".temp/mac-video-profile"

type CaptureCommand struct {
	Name        string
	Executable  string
	Args        []string
	Filename    string
	Optional    bool
	Timeout     time.Duration
	Description string
}

type ProcessGroup struct {
	Name        string
	Description string
	Queries     []string
	HotCPU      float64
}

type GroupSummary struct {
	Group     ProcessGroup
	Matches   []loadprofile.Process
	Hot       []loadprofile.Process
	TotalCPU  float64
	TotalRSSB int64
}

func CaptureDir(root string, now time.Time) string {
	root = strings.TrimSpace(root)
	if root == "" {
		root = DefaultArtifactRoot
	}
	return filepath.Join(root, "capture-"+now.UTC().Format("20060102T150405Z"))
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
			Name:        "hardware",
			Executable:  "/usr/sbin/sysctl",
			Args:        []string{"-n", "hw.ncpu", "hw.memsize", "machdep.cpu.brand_string"},
			Filename:    "hardware.txt",
			Optional:    true,
			Timeout:     5 * time.Second,
			Description: "CPU count, memory size, and CPU model",
		},
		{
			Name:        "displays",
			Executable:  "/usr/sbin/system_profiler",
			Args:        []string{"SPDisplaysDataType", "-detailLevel", "mini"},
			Filename:    "system-profiler-displays.txt",
			Optional:    true,
			Timeout:     30 * time.Second,
			Description: "GPU and display topology",
		},
		{
			Name:        "power",
			Executable:  "/usr/sbin/system_profiler",
			Args:        []string{"SPPowerDataType", "-detailLevel", "mini"},
			Filename:    "system-profiler-power.txt",
			Optional:    true,
			Timeout:     30 * time.Second,
			Description: "power and battery state",
		},
		{
			Name:        "ioreg_displays",
			Executable:  "/usr/sbin/ioreg",
			Args:        []string{"-lw0", "-r", "-c", "IODisplayConnect"},
			Filename:    "ioreg-displays.txt",
			Optional:    true,
			Timeout:     15 * time.Second,
			Description: "display connection registry state",
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
			Name:        "pmset_thermal",
			Executable:  "/usr/bin/pmset",
			Args:        []string{"-g", "therm"},
			Filename:    "pmset-thermal.txt",
			Optional:    true,
			Timeout:     10 * time.Second,
			Description: "thermal pressure snapshot",
		},
		{
			Name:        "memory_pressure",
			Executable:  "/usr/bin/memory_pressure",
			Args:        []string{"-Q"},
			Filename:    "memory-pressure.txt",
			Optional:    true,
			Timeout:     10 * time.Second,
			Description: "memory pressure snapshot",
		},
		{
			Name:        "vm_stat",
			Executable:  "/usr/bin/vm_stat",
			Filename:    "vm-stat.txt",
			Optional:    true,
			Timeout:     5 * time.Second,
			Description: "virtual memory counters",
		},
		{
			Name:        "top",
			Executable:  "/usr/bin/top",
			Args:        []string{"-l", "1", "-n", "60", "-stats", "pid,command,cpu,mem,threads,state,user"},
			Filename:    "top.txt",
			Optional:    true,
			Timeout:     15 * time.Second,
			Description: "top process snapshot",
		},
		{
			Name:        "ps",
			Executable:  "/bin/ps",
			Args:        loadprofile.PSArgs(),
			Filename:    "ps.txt",
			Timeout:     5 * time.Second,
			Description: "full process table",
		},
	}

	if includeLogs {
		commands = append(commands, CaptureCommand{
			Name:       "display_render_logs",
			Executable: "/usr/bin/log",
			Args: []string{
				"show",
				"--last", "20m",
				"--style", "compact",
				"--predicate", `process == "WindowServer" || process == "displaypolicyd" || eventMessage CONTAINS[c] "WindowServer" || eventMessage CONTAINS[c] "display" || eventMessage CONTAINS[c] "IOAccel" || eventMessage CONTAINS[c] "AGX" || eventMessage CONTAINS[c] "Metal" || eventMessage CONTAINS[c] "frame"`,
			},
			Filename:    "logs-display-render.txt",
			Optional:    true,
			Timeout:     30 * time.Second,
			Description: "recent WindowServer, display, GPU, Metal, and frame-related logs",
		})
	}

	return commands
}

func ProcessGroups() []ProcessGroup {
	return []ProcessGroup{
		{
			Name:        "compositor",
			Description: "WindowServer, Dock, and system UI processes that can make all animation look discrete when hot",
			Queries:     []string{"WindowServer", "/System/Library/CoreServices/Dock.app", "SystemUIServer", "ControlCenter"},
			HotCPU:      20,
		},
		{
			Name:        "display-services",
			Description: "display policy, brightness, and external display service processes",
			Queries:     []string{"displaypolicyd", "corebrightnessd", "universalaccessd", "Sidecar", "AirPlay"},
			HotCPU:      10,
		},
		{
			Name:        "gpu-media",
			Description: "media encode/decode and GPU-adjacent services",
			Queries:     []string{"VTDecoderXPCService", "VTEncoderXPCService", "mediaanalysisd", "photoanalysisd", "kernel_task"},
			HotCPU:      25,
		},
		{
			Name:        "docker-virtualization",
			Description: "Docker, VM, and virtualization workloads that can starve UI smoothness",
			Queries:     []string{"Docker", "com.docker", "vpnkit", "Virtualization", "VirtualizationService", "qemu-system", "colima", "lima", "OrbStack", "com.orbstack"},
			HotCPU:      40,
		},
		{
			Name:        "browser-electron-video",
			Description: "browser, Electron, conferencing, and video playback surfaces",
			Queries:     []string{"Safari", "Google Chrome", "Chromium", "Firefox", "Electron", "Slack", "Code Helper", "Zoom", "MTS Link", "Microsoft Teams"},
			HotCPU:      35,
		},
	}
}

func InterestingQueries() []string {
	seen := make(map[string]bool)
	var queries []string
	for _, group := range ProcessGroups() {
		for _, query := range group.Queries {
			key := strings.ToLower(query)
			if seen[key] {
				continue
			}
			seen[key] = true
			queries = append(queries, query)
		}
	}
	return queries
}

func SummarizeGroups(processes []loadprofile.Process, hotCPU float64) []GroupSummary {
	var summaries []GroupSummary
	for _, group := range ProcessGroups() {
		matches := loadprofile.FilterAny(processes, group.Queries)
		if len(matches) == 0 {
			continue
		}

		threshold := hotCPU
		if threshold <= 0 {
			threshold = group.HotCPU
		}

		var hot []loadprofile.Process
		for _, process := range matches {
			if process.CPU >= threshold {
				hot = append(hot, process)
			}
		}

		summaries = append(summaries, GroupSummary{
			Group:     group,
			Matches:   matches,
			Hot:       loadprofile.TopByCPU(hot, len(hot)),
			TotalCPU:  loadprofile.TotalCPU(matches),
			TotalRSSB: loadprofile.TotalRSSKB(matches) * 1024,
		})
	}
	return summaries
}

func TopInteresting(processes []loadprofile.Process, limit int) []loadprofile.Process {
	if limit <= 0 {
		return nil
	}
	matches := loadprofile.FilterAny(processes, InterestingQueries())
	return loadprofile.TopByCPU(matches, limit)
}

func SortSummariesByCPU(summaries []GroupSummary) []GroupSummary {
	out := append([]GroupSummary(nil), summaries...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].TotalCPU == out[j].TotalCPU {
			return out[i].Group.Name < out[j].Group.Name
		}
		return out[i].TotalCPU > out[j].TotalCPU
	})
	return out
}
