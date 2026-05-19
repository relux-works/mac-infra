package loadprofile

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

type Process struct {
	PID     int
	PPID    int
	User    string
	CPU     float64
	Memory  float64
	RSSKB   int64
	Elapsed string
	Command string
}

func ParsePS(output []byte) ([]Process, error) {
	var processes []Process
	var parseErrs []string

	for lineNo, raw := range strings.Split(string(output), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 8 {
			parseErrs = append(parseErrs, fmt.Sprintf("line %d: expected at least 8 fields", lineNo+1))
			continue
		}

		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			// Header rows from manually run ps output are harmless.
			continue
		}
		ppid, err := strconv.Atoi(fields[1])
		if err != nil {
			parseErrs = append(parseErrs, fmt.Sprintf("line %d: parse ppid: %v", lineNo+1, err))
			continue
		}
		cpu, err := strconv.ParseFloat(fields[3], 64)
		if err != nil {
			parseErrs = append(parseErrs, fmt.Sprintf("line %d: parse cpu: %v", lineNo+1, err))
			continue
		}
		mem, err := strconv.ParseFloat(fields[4], 64)
		if err != nil {
			parseErrs = append(parseErrs, fmt.Sprintf("line %d: parse memory: %v", lineNo+1, err))
			continue
		}
		rss, err := strconv.ParseInt(fields[5], 10, 64)
		if err != nil {
			parseErrs = append(parseErrs, fmt.Sprintf("line %d: parse rss: %v", lineNo+1, err))
			continue
		}

		processes = append(processes, Process{
			PID:     pid,
			PPID:    ppid,
			User:    fields[2],
			CPU:     cpu,
			Memory:  mem,
			RSSKB:   rss,
			Elapsed: fields[6],
			Command: strings.Join(fields[7:], " "),
		})
	}

	if len(processes) == 0 && len(parseErrs) > 0 {
		return nil, fmt.Errorf("parse ps output: %s", strings.Join(parseErrs, "; "))
	}
	return processes, nil
}

func TopByCPU(processes []Process, limit int) []Process {
	return top(processes, limit, func(left, right Process) bool {
		if left.CPU == right.CPU {
			return left.PID < right.PID
		}
		return left.CPU > right.CPU
	})
}

func TopByRSS(processes []Process, limit int) []Process {
	return top(processes, limit, func(left, right Process) bool {
		if left.RSSKB == right.RSSKB {
			return left.PID < right.PID
		}
		return left.RSSKB > right.RSSKB
	})
}

func Filter(processes []Process, query string) []Process {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil
	}
	queryLower := strings.ToLower(query)
	var matches []Process
	for _, process := range processes {
		if strconv.Itoa(process.PID) == query ||
			strings.Contains(strings.ToLower(process.Command), queryLower) ||
			strings.Contains(strings.ToLower(process.User), queryLower) {
			matches = append(matches, process)
		}
	}
	return SortByPID(matches)
}

func FilterAny(processes []Process, queries []string) []Process {
	seen := make(map[int]bool)
	var matches []Process
	for _, query := range queries {
		for _, process := range Filter(processes, query) {
			if seen[process.PID] {
				continue
			}
			seen[process.PID] = true
			matches = append(matches, process)
		}
	}
	return SortByPID(matches)
}

func WithDescendants(processes []Process, roots []Process) []Process {
	byParent := make(map[int][]Process)
	for _, process := range processes {
		byParent[process.PPID] = append(byParent[process.PPID], process)
	}

	seen := make(map[int]bool)
	queue := append([]Process(nil), roots...)
	var result []Process
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if seen[current.PID] {
			continue
		}
		seen[current.PID] = true
		result = append(result, current)
		queue = append(queue, byParent[current.PID]...)
	}
	return SortByPID(result)
}

func SortByPID(processes []Process) []Process {
	out := append([]Process(nil), processes...)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].PID < out[j].PID
	})
	return out
}

func TotalCPU(processes []Process) float64 {
	var total float64
	for _, process := range processes {
		total += process.CPU
	}
	return total
}

func TotalRSSKB(processes []Process) int64 {
	var total int64
	for _, process := range processes {
		total += process.RSSKB
	}
	return total
}

func PrintTable(w io.Writer, processes []Process) {
	fmt.Fprintf(w, "%7s %7s %-12s %7s %7s %10s %-10s %s\n", "PID", "PPID", "USER", "CPU%", "MEM%", "RSS", "ELAPSED", "COMMAND")
	for _, process := range processes {
		fmt.Fprintf(
			w,
			"%7d %7d %-12.12s %7.1f %7.1f %10s %-10s %s\n",
			process.PID,
			process.PPID,
			process.User,
			process.CPU,
			process.Memory,
			FormatBytes(process.RSSKB*1024),
			process.Elapsed,
			process.Command,
		)
	}
}

func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}
	value := float64(bytes)
	for _, suffix := range []string{"KB", "MB", "GB", "TB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f%s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1fPB", value/unit)
}

func TunnelQueries() []string {
	return []string{
		"sing-box",
		"vless-tun",
		"openconnect",
		"openconnect-tun",
		"vpn-core",
		"vpnagentd",
	}
}

func top(processes []Process, limit int, less func(Process, Process) bool) []Process {
	if limit <= 0 {
		return nil
	}
	out := append([]Process(nil), processes...)
	sort.SliceStable(out, func(i, j int) bool {
		return less(out[i], out[j])
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
