package audiosweep

import (
	"os"
	"testing"
	"time"
)

func TestEnsureCachedWAVRendersThenReuses(t *testing.T) {
	plan := smallCachePlan(t)
	root := t.TempDir()

	first, err := EnsureCachedWAV(root, plan, false)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Rendered {
		t.Fatal("first cache call did not render")
	}
	info1, err := os.Stat(first.Path)
	if err != nil {
		t.Fatal(err)
	}

	second, err := EnsureCachedWAV(root, plan, false)
	if err != nil {
		t.Fatal(err)
	}
	if second.Rendered {
		t.Fatal("second cache call rendered despite cache hit")
	}
	if second.Path != first.Path || second.Key != first.Key {
		t.Fatalf("cache identity changed: first=%#v second=%#v", first, second)
	}
	info2, err := os.Stat(second.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info2.ModTime() != info1.ModTime() {
		t.Fatalf("cache hit modified file time: before=%s after=%s", info1.ModTime(), info2.ModTime())
	}
}

func TestEnsureCachedWAVRerenderOverwritesCachedFile(t *testing.T) {
	plan := smallCachePlan(t)
	root := t.TempDir()

	first, err := EnsureCachedWAV(root, plan, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first.Path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	second, err := EnsureCachedWAV(root, plan, true)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Rendered {
		t.Fatal("rerender did not render")
	}
	if second.Path != first.Path {
		t.Fatalf("rerender path = %q, want %q", second.Path, first.Path)
	}
	info, err := os.Stat(second.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= int64(len("stale")) {
		t.Fatalf("rerendered file size = %d, want real wav", info.Size())
	}
}

func smallCachePlan(t *testing.T) Plan {
	t.Helper()
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
	return plan
}
