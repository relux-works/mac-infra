package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunGenerateWritesWAV(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "sweep.wav")
	var stdout, stderr bytes.Buffer

	code := run([]string{
		"generate",
		"--sample-rate", "8000",
		"--channels", "1",
		"--start-hz", "10",
		"--low-end-hz", "50",
		"--end-hz", "1000",
		"--duration", "100ms",
		"--low-duration", "50ms",
		"--low-step", "5ms",
		"--fade", "0s",
		"--out", outPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "wav: "+outPath) {
		t.Fatalf("stdout missing wav path: %s", stdout.String())
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("wav missing: %v", err)
	}
}

func TestRunGenerateRejects44kTargetAt48kSampleRate(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"generate", "--sample-rate", "48000", "--end-hz", "44000", "--out", filepath.Join(t.TempDir(), "bad.wav")}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run code = %d, want 1; stdout = %s stderr = %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "requires sample-rate") {
		t.Fatalf("stderr missing sample-rate guidance: %s", stderr.String())
	}
}

func TestRunUsageAndUnknownCommand(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"--help"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 0 {
			t.Fatalf("run %v code = %d, stderr = %s", args, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "mac-audio-sweep") {
			t.Fatalf("help missing command name: %s", stdout.String())
		}
	}

	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("run nil code = %d, want 2", code)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("usage missing: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"bogus"}, &stdout, &stderr); code != 2 {
		t.Fatalf("unknown code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("unknown stderr missing: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"device", "extra"}, &stdout, &stderr); code != 2 {
		t.Fatalf("device positional code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "no positional") {
		t.Fatalf("device positional stderr missing: %s", stderr.String())
	}
}

func TestDefaultWAVPathUsesAudioSweepTempRoot(t *testing.T) {
	path := defaultWAVPath()
	if !strings.Contains(path, ".temp/mac-audio-sweep/sweep-") || !strings.HasSuffix(path, ".wav") {
		t.Fatalf("default path = %q", path)
	}
}

func TestCleanAudioPlayerStrictRejectsSampleRateMismatch(t *testing.T) {
	output := &fakeOutputController{
		device: outputDevice{Name: "TA-22", NominalSampleRate: 48000, SampleRateSettable: true},
	}
	inner := &fakeStartPlayer{}
	player := cleanAudioPlayer{
		inner:      inner,
		output:     output,
		targetRate: 96000,
		policy:     outputRateStrict,
	}

	_, err := player.Start("/tmp/sweep.wav")
	if err == nil {
		t.Fatal("Start succeeded, want mismatch error")
	}
	if !strings.Contains(err.Error(), "refusing CoreAudio resampling") {
		t.Fatalf("error = %v, want resampling refusal", err)
	}
	if inner.starts != 0 {
		t.Fatalf("inner starts = %d, want 0", inner.starts)
	}
}

func TestCleanAudioPlayerSetRestoresOriginalSampleRate(t *testing.T) {
	output := &fakeOutputController{
		device:   outputDevice{Name: "TA-22", NominalSampleRate: 48000, SampleRateSettable: true},
		supports: true,
	}
	inner := &fakeStartPlayer{}
	player := cleanAudioPlayer{
		inner:      inner,
		output:     output,
		targetRate: 96000,
		policy:     outputRateSet,
	}

	running, err := player.Start("/tmp/sweep.wav")
	if err != nil {
		t.Fatal(err)
	}
	if output.device.NominalSampleRate != 96000 {
		t.Fatalf("rate after start = %.0f, want 96000", output.device.NominalSampleRate)
	}
	if inner.starts != 1 {
		t.Fatalf("inner starts = %d, want 1", inner.starts)
	}
	if err := running.Stop(); err != nil {
		t.Fatal(err)
	}
	if output.device.NominalSampleRate != 48000 {
		t.Fatalf("rate after stop = %.0f, want restore 48000", output.device.NominalSampleRate)
	}
}

func TestPreflightOutputRateSetRejectsUnsupportedTarget(t *testing.T) {
	output := &fakeOutputController{
		device:   outputDevice{Name: "Fixed", NominalSampleRate: 48000, SampleRateSettable: true},
		supports: false,
	}
	err := preflightOutputRate(output, 96000, outputRateSet)
	if err == nil {
		t.Fatal("preflight succeeded, want unsupported error")
	}
	if !strings.Contains(err.Error(), "does not report support") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseOutputRatePolicy(t *testing.T) {
	for _, raw := range []string{"set", "strict", "off", " SET "} {
		if _, err := parseOutputRatePolicy(raw); err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
	}
	if _, err := parseOutputRatePolicy("maybe"); err == nil {
		t.Fatal("parse maybe succeeded, want error")
	}
}

type fakeOutputController struct {
	device   outputDevice
	supports bool
	setErr   error
}

func (c *fakeOutputController) DefaultOutput() (outputDevice, error) {
	return c.device, nil
}

func (c *fakeOutputController) SupportsSampleRate(rate float64) (bool, error) {
	return c.supports, nil
}

func (c *fakeOutputController) SetSampleRate(rate float64) error {
	if c.setErr != nil {
		return c.setErr
	}
	c.device.NominalSampleRate = rate
	return nil
}

type fakeStartPlayer struct {
	starts int
}

func (p *fakeStartPlayer) Start(path string) (playback, error) {
	p.starts++
	return &fakeStopPlayback{}, nil
}

type fakeStopPlayback struct {
	stopped bool
}

func (p *fakeStopPlayback) Stop() error {
	p.stopped = true
	return nil
}
