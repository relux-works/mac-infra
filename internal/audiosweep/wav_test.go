package audiosweep

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteWAVWritesPCMHeaderAndData(t *testing.T) {
	plan, err := NewPlan(Options{
		SampleRate:  8000,
		Channels:    1,
		StartHz:     10,
		LowEndHz:    50,
		EndHz:       1000,
		Duration:    100 * time.Millisecond,
		LowDuration: 50 * time.Millisecond,
		LowStep:     5 * time.Millisecond,
		Amplitude:   0.2,
		Fade:        0,
	})
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := WriteWAV(&buf, plan); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	if string(data[0:4]) != "RIFF" || string(data[8:12]) != "WAVE" || string(data[36:40]) != "data" {
		t.Fatalf("invalid wav header: %q %q %q", data[0:4], data[8:12], data[36:40])
	}
	if got := binary.LittleEndian.Uint32(data[24:28]); got != 8000 {
		t.Fatalf("sample rate = %d, want 8000", got)
	}
	if got := binary.LittleEndian.Uint16(data[22:24]); got != 1 {
		t.Fatalf("channels = %d, want 1", got)
	}
	if got, want := binary.LittleEndian.Uint32(data[40:44]), uint32(8000*0.1*2); got != want {
		t.Fatalf("data bytes = %d, want %d", got, want)
	}
	if len(data) != 44+int(binary.LittleEndian.Uint32(data[40:44])) {
		t.Fatalf("file size = %d, header data size = %d", len(data), binary.LittleEndian.Uint32(data[40:44]))
	}
}

func TestWriteWAVFileCreatesPrivateArtifact(t *testing.T) {
	plan, err := NewPlan(Options{
		SampleRate:  8000,
		Channels:    1,
		StartHz:     10,
		LowEndHz:    50,
		EndHz:       1000,
		Duration:    20 * time.Millisecond,
		LowDuration: 10 * time.Millisecond,
		LowStep:     time.Millisecond,
		Amplitude:   0.2,
		Fade:        0,
	})
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "nested", "sweep.wav")
	if err := WriteWAVFile(path, plan); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("wav mode = %o, want 0600", got)
	}
}

func TestFadeEnvelope(t *testing.T) {
	duration := time.Second
	fade := 100 * time.Millisecond
	tests := []struct {
		name    string
		elapsed time.Duration
		want    float64
	}{
		{name: "disabled", elapsed: 10 * time.Millisecond, want: 1},
		{name: "fade in", elapsed: 50 * time.Millisecond, want: 0.5},
		{name: "middle", elapsed: 500 * time.Millisecond, want: 1},
		{name: "fade out", elapsed: 950 * time.Millisecond, want: 0.5},
		{name: "done", elapsed: duration, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFade := fade
			if tt.name == "disabled" {
				gotFade = 0
			}
			if got := fadeEnvelope(tt.elapsed, duration, gotFade); got < tt.want-0.001 || got > tt.want+0.001 {
				t.Fatalf("fadeEnvelope = %.3f, want %.3f", got, tt.want)
			}
		})
	}
}
