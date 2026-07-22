package audiosweep

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"
)

func WriteWAVFile(path string, plan Plan) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create wav: %w", err)
	}
	if err := WriteWAV(file, plan); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close wav: %w", err)
	}
	return nil
}

func WriteWAV(w io.Writer, plan Plan) error {
	opts := plan.Options
	totalFrames := int64(math.Round(opts.Duration.Seconds() * float64(opts.SampleRate)))
	dataBytes := totalFrames * int64(opts.Channels) * 2
	if dataBytes > math.MaxUint32-44 {
		return fmt.Errorf("wav is too large for PCM RIFF")
	}

	if err := writeWAVHeader(w, opts.SampleRate, opts.Channels, uint32(dataBytes)); err != nil {
		return err
	}

	var phase float64
	frame := make([]byte, opts.Channels*2)
	for i := int64(0); i < totalFrames; i++ {
		elapsed := time.Duration(float64(i) / float64(opts.SampleRate) * float64(time.Second))
		hz := plan.FrequencyAt(elapsed)
		phase += 2 * math.Pi * hz / float64(opts.SampleRate)
		sample := math.Sin(phase) * opts.Amplitude * fadeEnvelope(elapsed, opts.Duration, opts.Fade)
		pcm := int16(math.Round(sample * math.MaxInt16))
		for ch := 0; ch < opts.Channels; ch++ {
			binary.LittleEndian.PutUint16(frame[ch*2:], uint16(pcm))
		}
		if _, err := w.Write(frame); err != nil {
			return fmt.Errorf("write pcm: %w", err)
		}
	}
	return nil
}

func writeWAVHeader(w io.Writer, sampleRate int, channels int, dataBytes uint32) error {
	byteRate := uint32(sampleRate * channels * 2)
	blockAlign := uint16(channels * 2)
	chunkSize := uint32(36) + dataBytes

	if _, err := w.Write([]byte("RIFF")); err != nil {
		return fmt.Errorf("write riff header: %w", err)
	}
	for _, value := range []any{
		chunkSize,
		[]byte("WAVE"),
		[]byte("fmt "),
		uint32(16),
		uint16(1),
		uint16(channels),
		uint32(sampleRate),
		byteRate,
		blockAlign,
		uint16(16),
		[]byte("data"),
		dataBytes,
	} {
		switch v := value.(type) {
		case []byte:
			if _, err := w.Write(v); err != nil {
				return fmt.Errorf("write wav header: %w", err)
			}
		default:
			if err := binary.Write(w, binary.LittleEndian, v); err != nil {
				return fmt.Errorf("write wav header: %w", err)
			}
		}
	}
	return nil
}

func fadeEnvelope(elapsed, duration, fade time.Duration) float64 {
	if fade <= 0 {
		return 1
	}
	if elapsed < fade {
		return elapsed.Seconds() / fade.Seconds()
	}
	if remaining := duration - elapsed; remaining < fade {
		if remaining <= 0 {
			return 0
		}
		return remaining.Seconds() / fade.Seconds()
	}
	return 1
}
