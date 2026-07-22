package audiosweep

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type CacheResult struct {
	Path     string
	Key      string
	Rendered bool
}

func CachePath(root string, plan Plan) (string, string, error) {
	if root == "" {
		root = filepath.Join(DefaultArtifactRoot, "cache")
	}
	key, err := cacheKey(plan)
	if err != nil {
		return "", "", err
	}
	return filepath.Join(root, "sweep-"+key+".wav"), key, nil
}

func EnsureCachedWAV(root string, plan Plan, rerender bool) (CacheResult, error) {
	path, key, err := CachePath(root, plan)
	if err != nil {
		return CacheResult{}, err
	}
	if !rerender {
		if info, err := os.Stat(path); err == nil && info.Size() > 44 {
			return CacheResult{Path: path, Key: key, Rendered: false}, nil
		} else if err != nil && !os.IsNotExist(err) {
			return CacheResult{}, fmt.Errorf("stat cached wav: %w", err)
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return CacheResult{}, fmt.Errorf("create cache dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".render-*.wav")
	if err != nil {
		return CacheResult{}, fmt.Errorf("create temp wav: %w", err)
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return CacheResult{}, fmt.Errorf("close temp wav: %w", err)
	}
	if err := WriteWAVFile(tmpPath, plan); err != nil {
		_ = os.Remove(tmpPath)
		return CacheResult{}, err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return CacheResult{}, fmt.Errorf("install cached wav: %w", err)
	}
	return CacheResult{Path: path, Key: key, Rendered: true}, nil
}

func cacheKey(plan Plan) (string, error) {
	opts := plan.Options
	payload := struct {
		Schema      int     `json:"schema"`
		SampleRate  int     `json:"sample_rate"`
		Channels    int     `json:"channels"`
		StartHz     float64 `json:"start_hz"`
		LowEndHz    float64 `json:"low_end_hz"`
		EndHz       float64 `json:"end_hz"`
		DurationNS  int64   `json:"duration_ns"`
		LowDurNS    int64   `json:"low_duration_ns"`
		LowStepNS   int64   `json:"low_step_ns"`
		Amplitude   float64 `json:"amplitude"`
		FadeNS      int64   `json:"fade_ns"`
		Generator   string  `json:"generator"`
		GeneratedAt int64   `json:"generated_at,omitempty"`
	}{
		Schema:     1,
		SampleRate: opts.SampleRate,
		Channels:   opts.Channels,
		StartHz:    opts.StartHz,
		LowEndHz:   opts.LowEndHz,
		EndHz:      opts.EndHz,
		DurationNS: int64(opts.Duration / time.Nanosecond),
		LowDurNS:   int64(opts.LowDuration / time.Nanosecond),
		LowStepNS:  int64(opts.LowStep / time.Nanosecond),
		Amplitude:  opts.Amplitude,
		FadeNS:     int64(opts.Fade / time.Nanosecond),
		Generator:  "mac-audio-sweep-pcm16-v1",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal cache key: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:16], nil
}
