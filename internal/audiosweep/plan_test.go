package audiosweep

import (
	"strings"
	"testing"
	"time"
)

func TestDefaultPlanStartsSlowThenAcceleratesThroughLowRamp(t *testing.T) {
	plan, err := NewPlan(DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}

	if got := plan.FrequencyAt(0); got != 1 {
		t.Fatalf("start frequency = %v, want 1 Hz", got)
	}
	if got := plan.FrequencyAt(5 * time.Second); got < 1.8 || got > 2.3 {
		t.Fatalf("frequency at 5s = %.3f Hz, want near 2 Hz", got)
	}
	if got := plan.FrequencyAt(plan.Options.LowDuration); got < 49.99 || got > 50.01 {
		t.Fatalf("frequency at low end = %.6f Hz, want 50 Hz", got)
	}
	if got := plan.FrequencyAt(plan.Options.Duration); got != 44000 {
		t.Fatalf("end frequency = %v, want 44000 Hz", got)
	}
	if startSlope, laterSlope := plan.SlopeAt(0), plan.SlopeAt(30*time.Second); laterSlope <= startSlope {
		t.Fatalf("low ramp did not accelerate: start slope %.3f later %.3f", startSlope, laterSlope)
	}
}

func TestPlanRejectsTargetAtOrAboveNyquist(t *testing.T) {
	opts := DefaultOptions()
	opts.SampleRate = 48000
	_, err := NewPlan(opts)
	if err == nil {
		t.Fatal("NewPlan succeeded, want Nyquist error")
	}
	if !strings.Contains(err.Error(), "requires sample-rate") {
		t.Fatalf("error = %v, want sample-rate guidance", err)
	}
}

func TestPlanProgressSegmentsNyquistAndHighSlope(t *testing.T) {
	plan, err := NewPlan(DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}

	if got := plan.NyquistHz(); got != 48000 {
		t.Fatalf("nyquist = %v, want 48000", got)
	}
	if got := plan.ProgressAt(-time.Second); got != 0 {
		t.Fatalf("negative progress = %v, want 0", got)
	}
	if got := plan.ProgressAt(plan.Options.Duration + time.Second); got != 1 {
		t.Fatalf("completed progress = %v, want 1", got)
	}
	if got := plan.SegmentAt(-time.Second); got != "low" {
		t.Fatalf("negative segment = %q, want low", got)
	}
	if got := plan.SegmentAt(plan.Options.LowDuration + time.Second); got != "high" {
		t.Fatalf("high segment = %q, want high", got)
	}
	if got := plan.SegmentAt(plan.Options.Duration + time.Second); got != "done" {
		t.Fatalf("done segment = %q, want done", got)
	}
	if got := plan.SlopeAt(plan.Options.LowDuration + time.Second); got <= 0 {
		t.Fatalf("high slope = %v, want positive", got)
	}
}

func TestLinearLowRampWhenLowDurationMatchesInitialPace(t *testing.T) {
	plan, err := NewPlan(Options{
		SampleRate:  8000,
		Channels:    1,
		StartHz:     10,
		LowEndHz:    20,
		EndHz:       1000,
		Duration:    2 * time.Second,
		LowDuration: time.Second,
		LowStep:     100 * time.Millisecond,
		Amplitude:   0.2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.FrequencyAt(500 * time.Millisecond); got < 14.99 || got > 15.01 {
		t.Fatalf("mid low frequency = %.4f Hz, want 15 Hz", got)
	}
	if got := plan.SlopeAt(500 * time.Millisecond); got < 9.99 || got > 10.01 {
		t.Fatalf("linear low slope = %.4f Hz/s, want 10", got)
	}
}

func TestPlanValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		want string
	}{
		{name: "sample rate", opts: Options{SampleRate: -1}, want: "sample-rate"},
		{name: "channels", opts: Options{Channels: 3}, want: "channels"},
		{name: "start", opts: Options{StartHz: -1}, want: "start-hz"},
		{name: "low end", opts: Options{StartHz: 10, LowEndHz: 10}, want: "low-end-hz"},
		{name: "end", opts: Options{LowEndHz: 100, EndHz: 90}, want: "end-hz"},
		{name: "duration", opts: Options{Duration: -time.Second}, want: "duration"},
		{name: "low duration", opts: Options{LowDuration: -time.Second}, want: "low-duration"},
		{name: "low duration too long", opts: Options{Duration: time.Second, LowDuration: time.Second}, want: "low-duration"},
		{name: "low step", opts: Options{LowStep: -time.Second}, want: "low-step"},
		{name: "amplitude", opts: Options{Amplitude: 2}, want: "amplitude"},
		{name: "fade", opts: Options{Fade: -time.Second}, want: "fade"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPlan(tt.opts)
			if err == nil {
				t.Fatal("NewPlan succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestFormatHz(t *testing.T) {
	tests := map[float64]string{
		5:     "5.0 Hz",
		999:   "999.0 Hz",
		1200:  "1.20 kHz",
		44000: "44.0 kHz",
	}
	for hz, want := range tests {
		if got := FormatHz(hz); got != want {
			t.Fatalf("FormatHz(%v) = %q, want %q", hz, got, want)
		}
	}
}
