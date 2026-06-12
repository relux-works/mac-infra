package simcleanup

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

type RuntimeCandidate struct {
	Identifier        string   `json:"identifier"`
	RuntimeIdentifier string   `json:"runtimeIdentifier"`
	Platform          string   `json:"platform"`
	Version           string   `json:"version"`
	Build             string   `json:"build"`
	Kind              string   `json:"kind"`
	State             string   `json:"state"`
	Path              string   `json:"path"`
	RuntimeBundlePath string   `json:"runtimeBundlePath,omitempty"`
	SizeBytes         int64    `json:"sizeBytes"`
	Reason            string   `json:"reason"`
	DeleteCommand     []string `json:"deleteCommand"`
}

type RuntimeCleanupReport struct {
	GeneratedAt time.Time          `json:"generatedAt"`
	Candidates  []RuntimeCandidate `json:"candidates"`
	Totals      RuntimeTotals      `json:"totals"`
}

type RuntimeTotals struct {
	CandidateCount int   `json:"candidateCount"`
	Bytes          int64 `json:"bytes"`
}

type simctlRuntimeRecord struct {
	Identifier        string `json:"identifier"`
	RuntimeIdentifier string `json:"runtimeIdentifier"`
	PlatformID        string `json:"platformIdentifier"`
	Version           string `json:"version"`
	Build             string `json:"build"`
	Kind              string `json:"kind"`
	State             string `json:"state"`
	Path              string `json:"path"`
	RuntimeBundlePath string `json:"runtimeBundlePath"`
	SizeBytes         int64  `json:"sizeBytes"`
	Deletable         bool   `json:"deletable"`
}

func DetectUnsupportedRuntimes(ctx context.Context, xcrunPath string, now time.Time) (RuntimeCleanupReport, error) {
	if strings.TrimSpace(xcrunPath) == "" {
		xcrunPath = "/usr/bin/xcrun"
	}
	jsonData, err := runXcrun(ctx, xcrunPath, "simctl", "runtime", "list", "--json")
	if err != nil {
		return RuntimeCleanupReport{}, err
	}
	textData, err := runXcrun(ctx, xcrunPath, "simctl", "list", "runtimes")
	if err != nil {
		return RuntimeCleanupReport{}, err
	}
	return BuildRuntimeCleanupReport(jsonData, textData, xcrunPath, now)
}

func DeleteRuntime(ctx context.Context, xcrunPath string, identifier string) ([]byte, error) {
	if strings.TrimSpace(xcrunPath) == "" {
		xcrunPath = "/usr/bin/xcrun"
	}
	return runXcrun(ctx, xcrunPath, "simctl", "runtime", "delete", identifier)
}

func BuildRuntimeCleanupReport(jsonData []byte, runtimesText []byte, xcrunPath string, now time.Time) (RuntimeCleanupReport, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	if strings.TrimSpace(xcrunPath) == "" {
		xcrunPath = "/usr/bin/xcrun"
	}

	records, err := parseRuntimeListJSON(jsonData)
	if err != nil {
		return RuntimeCleanupReport{}, err
	}
	unavailableReasons := ParseUnavailableRuntimeReasons(string(runtimesText))

	var candidates []RuntimeCandidate
	for _, record := range records {
		reason, unavailable := unavailableReasons[record.RuntimeIdentifier]
		if !unavailable || !record.Deletable {
			continue
		}
		candidates = append(candidates, RuntimeCandidate{
			Identifier:        record.Identifier,
			RuntimeIdentifier: record.RuntimeIdentifier,
			Platform:          platformName(record.PlatformID, record.RuntimeIdentifier),
			Version:           record.Version,
			Build:             record.Build,
			Kind:              record.Kind,
			State:             record.State,
			Path:              record.Path,
			RuntimeBundlePath: record.RuntimeBundlePath,
			SizeBytes:         record.SizeBytes,
			Reason:            reason,
			DeleteCommand:     []string{xcrunPath, "simctl", "runtime", "delete", record.Identifier},
		})
	}
	sort.Slice(candidates, func(i, j int) bool {
		left := candidates[i]
		right := candidates[j]
		if left.Platform != right.Platform {
			return left.Platform < right.Platform
		}
		if left.Version != right.Version {
			return left.Version < right.Version
		}
		return left.Build < right.Build
	})

	report := RuntimeCleanupReport{
		GeneratedAt: now,
		Candidates:  candidates,
	}
	for _, candidate := range candidates {
		report.Totals.CandidateCount++
		report.Totals.Bytes += candidate.SizeBytes
	}
	return report, nil
}

func ParseUnavailableRuntimeReasons(text string) map[string]string {
	reasons := map[string]string{}
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "==") || strings.HasPrefix(line, "--") {
			continue
		}
		separator := " - "
		separatorIndex := strings.LastIndex(line, separator)
		if separatorIndex < 0 {
			continue
		}
		tail := line[separatorIndex+len(separator):]
		marker := " (unavailable,"
		markerIndex := strings.Index(tail, marker)
		if markerIndex < 0 {
			continue
		}
		runtimeIdentifier := strings.TrimSpace(tail[:markerIndex])
		reason := strings.TrimSpace(tail[markerIndex+len(marker):])
		reason = strings.TrimSuffix(reason, ")")
		reason = strings.TrimSpace(reason)
		if runtimeIdentifier != "" {
			reasons[runtimeIdentifier] = reason
		}
	}
	return reasons
}

func parseRuntimeListJSON(data []byte) ([]simctlRuntimeRecord, error) {
	var byID map[string]simctlRuntimeRecord
	if err := json.Unmarshal(data, &byID); err != nil {
		return nil, fmt.Errorf("parse simctl runtime list json: %w", err)
	}
	records := make([]simctlRuntimeRecord, 0, len(byID))
	for key, record := range byID {
		if record.Identifier == "" {
			record.Identifier = key
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Identifier < records[j].Identifier
	})
	return records, nil
}

func platformName(platformID string, runtimeIdentifier string) string {
	switch platformID {
	case "com.apple.platform.iphonesimulator":
		return "iOS"
	case "com.apple.platform.watchsimulator":
		return "watchOS"
	case "com.apple.platform.appletvsimulator":
		return "tvOS"
	case "com.apple.platform.xrOSSimulator":
		return "visionOS"
	}
	const prefix = "com.apple.CoreSimulator.SimRuntime."
	name := strings.TrimPrefix(runtimeIdentifier, prefix)
	if name == runtimeIdentifier || name == "" {
		return platformID
	}
	if idx := strings.Index(name, "-"); idx > 0 {
		return name[:idx]
	}
	return name
}

func runXcrun(ctx context.Context, xcrunPath string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, xcrunPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s %s failed: %w: %s", xcrunPath, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}
