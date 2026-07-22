package audiosweep

import (
	"fmt"
	"math"
	"time"
)

const DefaultArtifactRoot = ".temp/mac-audio-sweep"

type Options struct {
	SampleRate  int
	Channels    int
	StartHz     float64
	LowEndHz    float64
	EndHz       float64
	Duration    time.Duration
	LowDuration time.Duration
	LowStep     time.Duration
	Amplitude   float64
	Fade        time.Duration
}

type Plan struct {
	Options Options
	lowK    float64
}

func DefaultOptions() Options {
	return Options{
		SampleRate:  96000,
		Channels:    2,
		StartHz:     1,
		LowEndHz:    50,
		EndHz:       44000,
		Duration:    180 * time.Second,
		LowDuration: 90 * time.Second,
		LowStep:     5 * time.Second,
		Amplitude:   0.20,
		Fade:        50 * time.Millisecond,
	}
}

func NewPlan(opts Options) (Plan, error) {
	opts = withDefaults(opts)
	if err := validate(opts); err != nil {
		return Plan{}, err
	}
	lowK, err := solveLowAcceleration(opts)
	if err != nil {
		return Plan{}, err
	}
	return Plan{Options: opts, lowK: lowK}, nil
}

func (p Plan) FrequencyAt(elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return p.Options.StartHz
	}
	if elapsed >= p.Options.Duration {
		return p.Options.EndHz
	}

	if elapsed <= p.Options.LowDuration {
		t := elapsed.Seconds()
		v0 := p.lowStartSlope()
		if p.lowK == 0 {
			return clampHz(p.Options.StartHz+v0*t, p.Options.StartHz, p.Options.LowEndHz)
		}
		f := p.Options.StartHz + (v0/p.lowK)*(math.Exp(p.lowK*t)-1)
		return clampHz(f, p.Options.StartHz, p.Options.LowEndHz)
	}

	highDuration := (p.Options.Duration - p.Options.LowDuration).Seconds()
	u := (elapsed - p.Options.LowDuration).Seconds() / highDuration
	f := p.Options.LowEndHz * math.Pow(p.Options.EndHz/p.Options.LowEndHz, u)
	return clampHz(f, p.Options.LowEndHz, p.Options.EndHz)
}

func (p Plan) SlopeAt(elapsed time.Duration) float64 {
	if elapsed < 0 {
		elapsed = 0
	}
	if elapsed <= p.Options.LowDuration {
		if p.lowK == 0 {
			return p.lowStartSlope()
		}
		return p.lowStartSlope() * math.Exp(p.lowK*elapsed.Seconds())
	}
	if elapsed >= p.Options.Duration {
		elapsed = p.Options.Duration
	}
	f := p.FrequencyAt(elapsed)
	highDuration := (p.Options.Duration - p.Options.LowDuration).Seconds()
	return f * math.Log(p.Options.EndHz/p.Options.LowEndHz) / highDuration
}

func (p Plan) SegmentAt(elapsed time.Duration) string {
	switch {
	case elapsed < 0:
		return "low"
	case elapsed <= p.Options.LowDuration:
		return "low"
	case elapsed < p.Options.Duration:
		return "high"
	default:
		return "done"
	}
}

func (p Plan) ProgressAt(elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	if elapsed >= p.Options.Duration {
		return 1
	}
	return elapsed.Seconds() / p.Options.Duration.Seconds()
}

func (p Plan) NyquistHz() float64 {
	return float64(p.Options.SampleRate) / 2
}

func FormatHz(hz float64) string {
	if hz < 1000 {
		return fmt.Sprintf("%.1f Hz", hz)
	}
	if hz < 10000 {
		return fmt.Sprintf("%.2f kHz", hz/1000)
	}
	return fmt.Sprintf("%.1f kHz", hz/1000)
}

func (p Plan) lowStartSlope() float64 {
	return 1 / p.Options.LowStep.Seconds()
}

func withDefaults(opts Options) Options {
	def := DefaultOptions()
	if opts.SampleRate == 0 {
		opts.SampleRate = def.SampleRate
	}
	if opts.Channels == 0 {
		opts.Channels = def.Channels
	}
	if opts.StartHz == 0 {
		opts.StartHz = def.StartHz
	}
	if opts.LowEndHz == 0 {
		opts.LowEndHz = def.LowEndHz
	}
	if opts.EndHz == 0 {
		opts.EndHz = def.EndHz
	}
	if opts.Duration == 0 {
		opts.Duration = def.Duration
	}
	if opts.LowDuration == 0 {
		opts.LowDuration = def.LowDuration
	}
	if opts.LowStep == 0 {
		opts.LowStep = def.LowStep
	}
	if opts.Amplitude == 0 {
		opts.Amplitude = def.Amplitude
	}
	return opts
}

func validate(opts Options) error {
	if opts.SampleRate <= 0 {
		return fmt.Errorf("sample-rate must be positive")
	}
	if opts.Channels != 1 && opts.Channels != 2 {
		return fmt.Errorf("channels must be 1 or 2")
	}
	if opts.StartHz <= 0 {
		return fmt.Errorf("start-hz must be > 0; use 1 Hz for a 0-ish exponential sweep")
	}
	if opts.LowEndHz <= opts.StartHz {
		return fmt.Errorf("low-end-hz must be greater than start-hz")
	}
	if opts.EndHz <= opts.LowEndHz {
		return fmt.Errorf("end-hz must be greater than low-end-hz")
	}
	if opts.EndHz >= float64(opts.SampleRate)/2 {
		return fmt.Errorf("end-hz %.1f requires sample-rate greater than %.1f Hz", opts.EndHz, opts.EndHz*2)
	}
	if opts.Duration <= 0 {
		return fmt.Errorf("duration must be positive")
	}
	if opts.LowDuration <= 0 {
		return fmt.Errorf("low-duration must be positive")
	}
	if opts.LowDuration >= opts.Duration {
		return fmt.Errorf("low-duration must be shorter than duration")
	}
	if opts.LowStep <= 0 {
		return fmt.Errorf("low-step must be positive")
	}
	if opts.Amplitude <= 0 || opts.Amplitude > 1 {
		return fmt.Errorf("amplitude must be in (0, 1]")
	}
	if opts.Fade < 0 {
		return fmt.Errorf("fade must be non-negative")
	}
	if opts.Fade*2 >= opts.Duration {
		return fmt.Errorf("fade is too long for duration")
	}
	maxLowDuration := time.Duration((opts.LowEndHz - opts.StartHz) * opts.LowStep.Seconds() * float64(time.Second))
	if opts.LowDuration > maxLowDuration {
		return fmt.Errorf("low-duration %s is too long for low-step %s and %.1f-%.1f Hz", opts.LowDuration, opts.LowStep, opts.StartHz, opts.LowEndHz)
	}
	return nil
}

func solveLowAcceleration(opts Options) (float64, error) {
	delta := opts.LowEndHz - opts.StartHz
	v0 := 1 / opts.LowStep.Seconds()
	t := opts.LowDuration.Seconds()
	ratio := delta / (v0 * t)
	if ratio < 1-1e-9 {
		return 0, fmt.Errorf("low curve cannot accelerate with requested low-duration and low-step")
	}
	if math.Abs(ratio-1) < 1e-9 {
		return 0, nil
	}

	lo, hi := 0.0, 1.0
	for lowCurveRatio(hi) < ratio {
		hi *= 2
		if hi > 700 {
			return 0, fmt.Errorf("low curve acceleration is too steep")
		}
	}
	for i := 0; i < 80; i++ {
		mid := (lo + hi) / 2
		if lowCurveRatio(mid) < ratio {
			lo = mid
		} else {
			hi = mid
		}
	}
	return ((lo + hi) / 2) / t, nil
}

func lowCurveRatio(x float64) float64 {
	if x == 0 {
		return 1
	}
	return math.Expm1(x) / x
}

func clampHz(hz, minHz, maxHz float64) float64 {
	if hz < minHz {
		return minHz
	}
	if hz > maxHz {
		return maxHz
	}
	return hz
}
