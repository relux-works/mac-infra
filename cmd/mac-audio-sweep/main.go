package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/relux-works/mac-infra/internal/audiodevice"
	"github.com/relux-works/mac-infra/internal/audiosweep"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stdout)
		return 2
	}

	switch args[0] {
	case "device":
		return runDevice(args[1:], stdout, stderr)
	case "generate":
		return runGenerate(args[1:], stdout, stderr)
	case "tui", "play":
		return runTUI(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "mac-audio-sweep %s %s %s\n", Version, Commit, BuildDate)
		return 0
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runDevice(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("device", flag.ContinueOnError)
	fs.SetOutput(stderr)
	targetRate := fs.Float64("target-rate", float64(audiosweep.DefaultOptions().SampleRate), "sample rate to check against the default output device")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "device takes no positional arguments")
		return 2
	}

	output := coreAudioOutputController{}
	device, err := output.DefaultOutput()
	if err != nil {
		fmt.Fprintf(stderr, "device failed: %v\n", err)
		return 1
	}
	supported, err := output.SupportsSampleRate(*targetRate)
	if err != nil {
		fmt.Fprintf(stderr, "device failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "output: %s\n", device.Name)
	fmt.Fprintf(stdout, "sample_rate: %s\n", formatSampleRate(device.NominalSampleRate))
	fmt.Fprintf(stdout, "sample_rate_settable: %s\n", yesNo(device.SampleRateSettable))
	fmt.Fprintf(stdout, "supports_%s: %s\n", strings.ReplaceAll(formatSampleRate(*targetRate), " ", "_"), yesNo(supported))
	return 0
}

func runGenerate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	planFlags := addPlanFlags(fs)
	out := fs.String("out", "", "output WAV path; default writes under .temp/mac-audio-sweep")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	plan, err := audiosweep.NewPlan(planFlags.options())
	if err != nil {
		fmt.Fprintf(stderr, "generate failed: %v\n", err)
		return 1
	}
	path := *out
	if strings.TrimSpace(path) == "" {
		path = defaultWAVPath()
	}
	if err := audiosweep.WriteWAVFile(path, plan); err != nil {
		fmt.Fprintf(stderr, "generate failed: %v\n", err)
		return 1
	}
	printPlanSummary(stdout, "wav", path, plan)
	return 0
}

func runTUI(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	planFlags := addPlanFlags(fs)
	artifactDir := fs.String("artifact-dir", audiosweep.DefaultArtifactRoot, "directory for temporary WAV artifacts")
	cacheDir := fs.String("cache-dir", filepath.Join(audiosweep.DefaultArtifactRoot, "cache"), "directory for cached WAV artifacts")
	afplayPath := fs.String("afplay", "/usr/bin/afplay", "afplay executable path")
	keepWAV := fs.Bool("keep-wav", false, "keep the generated WAV after the TUI exits")
	noCache := fs.Bool("no-cache", false, "render a one-shot WAV instead of using the cache")
	rerender := fs.Bool("rerender", false, "force re-rendering the cached WAV for the current parameters")
	outputRate := fs.String("output-rate", string(outputRateSet), "output sample-rate policy: set, strict, or off")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	policy, err := parseOutputRatePolicy(*outputRate)
	if err != nil {
		fmt.Fprintf(stderr, "tui failed: %v\n", err)
		return 2
	}
	plan, err := audiosweep.NewPlan(planFlags.options())
	if err != nil {
		fmt.Fprintf(stderr, "tui failed: %v\n", err)
		return 1
	}
	output := coreAudioOutputController{}
	if err := preflightOutputRate(output, float64(plan.Options.SampleRate), policy); err != nil {
		fmt.Fprintf(stderr, "tui failed: %v\n", err)
		return 1
	}
	path := ""
	if *noCache {
		path = filepath.Join(*artifactDir, "sweep-"+time.Now().Format("20060102-150405")+".wav")
		fmt.Fprintf(stderr, "rendering local wav: %s\n", path)
		if err := audiosweep.WriteWAVFile(path, plan); err != nil {
			fmt.Fprintf(stderr, "tui failed: %v\n", err)
			return 1
		}
		if !*keepWAV {
			defer os.Remove(path)
		}
	} else {
		result, err := audiosweep.EnsureCachedWAV(*cacheDir, plan, *rerender)
		if err != nil {
			fmt.Fprintf(stderr, "tui failed: %v\n", err)
			return 1
		}
		path = result.Path
		cacheStatus := "hit"
		if result.Rendered {
			cacheStatus = "rendered"
			if *rerender {
				cacheStatus = "rerendered"
			}
		}
		fmt.Fprintf(stderr, "cache: %s %s\n", cacheStatus, path)
	}

	player := cleanAudioPlayer{
		inner:      afplayPlayer{executable: *afplayPath},
		output:     output,
		targetRate: float64(plan.Options.SampleRate),
		policy:     policy,
	}
	p := tea.NewProgram(newModel(plan, path, player, time.Now))
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(stderr, "tui failed: %v\n", err)
		return 1
	}
	return 0
}

type planFlagSet struct {
	sampleRate  *int
	channels    *int
	startHz     *float64
	lowEndHz    *float64
	endHz       *float64
	duration    *time.Duration
	lowDuration *time.Duration
	lowStep     *time.Duration
	amplitude   *float64
	fade        *time.Duration
}

func addPlanFlags(fs *flag.FlagSet) planFlagSet {
	def := audiosweep.DefaultOptions()
	return planFlagSet{
		sampleRate:  fs.Int("sample-rate", def.SampleRate, "WAV sample rate; 96 kHz is required for a 44 kHz target"),
		channels:    fs.Int("channels", def.Channels, "audio channels: 1 mono or 2 stereo"),
		startHz:     fs.Float64("start-hz", def.StartHz, "start frequency; use 1 Hz for a 0-ish exponential sweep"),
		lowEndHz:    fs.Float64("low-end-hz", def.LowEndHz, "end of slow low-frequency ramp"),
		endHz:       fs.Float64("end-hz", def.EndHz, "target frequency"),
		duration:    fs.Duration("duration", def.Duration, "total sweep duration"),
		lowDuration: fs.Duration("low-duration", def.LowDuration, "duration of smooth accelerating low-frequency ramp"),
		lowStep:     fs.Duration("low-step", def.LowStep, "initial low ramp pace; default starts near +1 Hz per 5s"),
		amplitude:   fs.Float64("amplitude", def.Amplitude, "linear amplitude in (0, 1]; keep low for hearing safety"),
		fade:        fs.Duration("fade", def.Fade, "fade-in/fade-out duration"),
	}
}

func (f planFlagSet) options() audiosweep.Options {
	return audiosweep.Options{
		SampleRate:  *f.sampleRate,
		Channels:    *f.channels,
		StartHz:     *f.startHz,
		LowEndHz:    *f.lowEndHz,
		EndHz:       *f.endHz,
		Duration:    *f.duration,
		LowDuration: *f.lowDuration,
		LowStep:     *f.lowStep,
		Amplitude:   *f.amplitude,
		Fade:        *f.fade,
	}
}

func printPlanSummary(w io.Writer, label string, path string, plan audiosweep.Plan) {
	fmt.Fprintf(w, "%s: %s\n", label, path)
	fmt.Fprintf(w, "duration: %s\n", plan.Options.Duration)
	fmt.Fprintf(w, "range: %s -> %s\n", audiosweep.FormatHz(plan.Options.StartHz), audiosweep.FormatHz(plan.Options.EndHz))
	fmt.Fprintf(w, "low_ramp: %s -> %s over %s, starts near +1 Hz / %s\n",
		audiosweep.FormatHz(plan.Options.StartHz),
		audiosweep.FormatHz(plan.Options.LowEndHz),
		plan.Options.LowDuration,
		plan.Options.LowStep,
	)
	fmt.Fprintf(w, "sample_rate: %d Hz\n", plan.Options.SampleRate)
	fmt.Fprintf(w, "nyquist: %s\n", audiosweep.FormatHz(plan.NyquistHz()))
}

func defaultWAVPath() string {
	return filepath.Join(audiosweep.DefaultArtifactRoot, "sweep-"+time.Now().Format("20060102-150405")+".wav")
}

type afplayPlayer struct {
	executable string
}

func (p afplayPlayer) Start(path string) (playback, error) {
	executable := p.executable
	if strings.TrimSpace(executable) == "" {
		executable = "/usr/bin/afplay"
	}
	cmd := exec.Command(executable, path)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start afplay: %w", err)
	}
	running := &processPlayback{
		cmd:  cmd,
		done: make(chan error, 1),
	}
	go func() {
		running.done <- cmd.Wait()
	}()
	return running, nil
}

type processPlayback struct {
	cmd     *exec.Cmd
	done    chan error
	once    sync.Once
	stopErr error
}

func (p *processPlayback) Stop() error {
	p.once.Do(func() {
		if p.cmd == nil || p.cmd.Process == nil {
			return
		}
		if err := p.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) && !strings.Contains(err.Error(), "process already finished") {
			p.stopErr = err
			return
		}
		select {
		case <-p.done:
		case <-time.After(2 * time.Second):
			p.stopErr = fmt.Errorf("afplay did not exit after kill")
		}
	})
	return p.stopErr
}

type outputRatePolicy string

const (
	outputRateSet    outputRatePolicy = "set"
	outputRateStrict outputRatePolicy = "strict"
	outputRateOff    outputRatePolicy = "off"
)

type outputDevice struct {
	Name               string
	NominalSampleRate  float64
	SampleRateSettable bool
}

type outputController interface {
	DefaultOutput() (outputDevice, error)
	SupportsSampleRate(rate float64) (bool, error)
	SetSampleRate(rate float64) error
}

type coreAudioOutputController struct{}

func (coreAudioOutputController) DefaultOutput() (outputDevice, error) {
	device, err := audiodevice.DefaultOutputDevice()
	if err != nil {
		return outputDevice{}, err
	}
	return outputDevice{
		Name:               device.Name,
		NominalSampleRate:  device.NominalSampleRate,
		SampleRateSettable: device.SampleRateSettable,
	}, nil
}

func (coreAudioOutputController) SupportsSampleRate(rate float64) (bool, error) {
	return audiodevice.SupportsDefaultOutputSampleRate(rate)
}

func (coreAudioOutputController) SetSampleRate(rate float64) error {
	return audiodevice.SetDefaultOutputSampleRate(rate)
}

type cleanAudioPlayer struct {
	inner      player
	output     outputController
	targetRate float64
	policy     outputRatePolicy
}

func (p cleanAudioPlayer) Start(path string) (playback, error) {
	if p.policy == outputRateOff {
		return p.inner.Start(path)
	}
	if p.output == nil {
		return nil, fmt.Errorf("missing output sample-rate controller")
	}

	before, err := p.output.DefaultOutput()
	if err != nil {
		return nil, err
	}
	changed := false
	if !sameRate(before.NominalSampleRate, p.targetRate) {
		if p.policy == outputRateStrict {
			return nil, sampleRateMismatchError(before, p.targetRate)
		}
		if !before.SampleRateSettable {
			return nil, fmt.Errorf("output device %q is fixed at %s; refusing to resample %s WAV", before.Name, formatSampleRate(before.NominalSampleRate), formatSampleRate(p.targetRate))
		}
		supported, err := p.output.SupportsSampleRate(p.targetRate)
		if err != nil {
			return nil, err
		}
		if !supported {
			return nil, fmt.Errorf("output device %q does not report support for %s", before.Name, formatSampleRate(p.targetRate))
		}
		if err := p.output.SetSampleRate(p.targetRate); err != nil {
			return nil, err
		}
		changed = true
		if err := waitForOutputRate(p.output, p.targetRate, 2*time.Second); err != nil {
			_ = p.output.SetSampleRate(before.NominalSampleRate)
			return nil, err
		}
	}

	running, err := p.inner.Start(path)
	if err != nil {
		if changed {
			_ = p.output.SetSampleRate(before.NominalSampleRate)
		}
		return nil, err
	}
	if !changed {
		return running, nil
	}
	return &cleanPlayback{
		inner:        running,
		output:       p.output,
		restoreRate:  before.NominalSampleRate,
		restoreLabel: before.Name,
	}, nil
}

type cleanPlayback struct {
	inner        playback
	output       outputController
	restoreRate  float64
	restoreLabel string
	once         sync.Once
	stopErr      error
}

func (p *cleanPlayback) Stop() error {
	p.once.Do(func() {
		if p.inner != nil {
			p.stopErr = p.inner.Stop()
		}
		if p.output != nil {
			if err := p.output.SetSampleRate(p.restoreRate); err != nil && p.stopErr == nil {
				p.stopErr = fmt.Errorf("restore output device %q to %s: %w", p.restoreLabel, formatSampleRate(p.restoreRate), err)
			}
		}
	})
	return p.stopErr
}

func parseOutputRatePolicy(raw string) (outputRatePolicy, error) {
	switch outputRatePolicy(strings.TrimSpace(strings.ToLower(raw))) {
	case outputRateSet:
		return outputRateSet, nil
	case outputRateStrict:
		return outputRateStrict, nil
	case outputRateOff:
		return outputRateOff, nil
	default:
		return "", fmt.Errorf("unknown output-rate policy %q; use set, strict, or off", raw)
	}
}

func preflightOutputRate(output outputController, targetRate float64, policy outputRatePolicy) error {
	if policy == outputRateOff {
		return nil
	}
	device, err := output.DefaultOutput()
	if err != nil {
		return err
	}
	if sameRate(device.NominalSampleRate, targetRate) {
		return nil
	}
	if policy == outputRateStrict {
		return sampleRateMismatchError(device, targetRate)
	}
	if !device.SampleRateSettable {
		return fmt.Errorf("output device %q is fixed at %s; cannot switch to %s for no-resample playback", device.Name, formatSampleRate(device.NominalSampleRate), formatSampleRate(targetRate))
	}
	supported, err := output.SupportsSampleRate(targetRate)
	if err != nil {
		return err
	}
	if !supported {
		return fmt.Errorf("output device %q does not report support for %s", device.Name, formatSampleRate(targetRate))
	}
	return nil
}

func waitForOutputRate(output outputController, targetRate float64, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		device, err := output.DefaultOutput()
		if err != nil {
			return err
		}
		if sameRate(device.NominalSampleRate, targetRate) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("output device %q stayed at %s after requesting %s", device.Name, formatSampleRate(device.NominalSampleRate), formatSampleRate(targetRate))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func sampleRateMismatchError(device outputDevice, targetRate float64) error {
	return fmt.Errorf("output device %q is at %s, WAV is %s; refusing CoreAudio resampling", device.Name, formatSampleRate(device.NominalSampleRate), formatSampleRate(targetRate))
}

func sameRate(a, b float64) bool {
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	return diff < 0.5
}

func formatSampleRate(rate float64) string {
	if sameRate(rate, float64(int(rate))) {
		return fmt.Sprintf("%.0f Hz", rate)
	}
	return fmt.Sprintf("%.2f Hz", rate)
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "mac-audio-sweep generates and plays local exponential-ish audio frequency sweeps.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  mac-audio-sweep device [--target-rate 96000]")
	fmt.Fprintln(w, "  mac-audio-sweep tui [--duration 3m] [--low-step 5s] [--end-hz 44000] [--output-rate set]")
	fmt.Fprintln(w, "  mac-audio-sweep generate [--out PATH] [--duration 3m] [--end-hz 44000]")
	fmt.Fprintln(w, "  mac-audio-sweep version")
}
