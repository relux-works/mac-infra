package firewallwatch

import (
	"encoding/json"
	"testing"
	"time"
)

// Maxima retain their first strictly-higher observation times across saves, ties and new watcher runs.
func TestHealthMaximaTimesPersistAcrossRuns(t *testing.T) {
	c := testConfig(t)
	s, err := OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	s.BeginCoverage(start)
	s.BeginSourceCoverage(SourceNetfilter, start)
	s.Coverage("").queueDepthAt(10, start)
	s.Coverage("").queueDepthAt(10, start.Add(time.Second))
	s.Coverage(SourceNetfilter).queueDepthAt(4, start.Add(2*time.Second))
	s.State.Health.Classification.observe(20, start.Add(3*time.Second))
	s.State.Health.Classification.observe(10, start.Add(4*time.Second))
	s.State.Health.Classification.observe(20, start.Add(5*time.Second))
	if err = s.Save(start.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// The next save persists the completed first save duration and its max_at.
	firstSave := s.State.Health.Save
	if err = s.Save(start.Add(2 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	if s.State.Health.Save.MaxAt == nil || firstSave.MaxAt == nil || !s.State.Health.Save.MaxAt.Equal(*firstSave.MaxAt) {
		t.Fatal("save maximum timestamp did not persist")
	}
	s.BeginCoverage(start.Add(3 * time.Minute))
	s.BeginSourceCoverage(SourceNetfilter, start.Add(3*time.Minute))
	s.Coverage("").queueDepthAt(10, start.Add(3*time.Minute))
	s.Coverage(SourceNetfilter).queueDepthAt(8, start.Add(4*time.Minute))
	s.State.Health.Classification.observe(20, start.Add(4*time.Minute))
	if err = s.Save(start.Add(5 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	h := s.State.Health
	for _, tc := range []struct {
		name string
		got  *time.Time
		want time.Time
	}{
		{"alf", h.LineQueueHighWater.MaxAt.ALF, start},
		{"netfilter", h.LineQueueHighWater.MaxAt.Netfilter, start.Add(4 * time.Minute)},
		{"classification", h.Classification.MaxAt, start.Add(3 * time.Second)},
	} {
		if tc.got == nil || !tc.got.Equal(tc.want) {
			t.Fatalf("%s maximum time: got %v, want %v", tc.name, tc.got, tc.want)
		}
	}
	if h.LineQueueHighWater.ALF != 10 || h.LineQueueHighWater.Netfilter != 8 || h.Classification.MaxNS != 20 || h.Classification.Count != 4 {
		t.Fatalf("maxima reset across runs: %+v", h)
	}
}

// Old nonzero maxima load without invented timestamps, and only a strictly higher sample assigns max_at.
func TestHealthLegacyMaximaUnknown(t *testing.T) {
	var h RunHealth
	if err := json.Unmarshal([]byte(`{"line_queue_high_water":{"alf":64,"netfilter":32},"save":{"last_ns":1,"max_ns":2,"count":3},"classification":{"last_ns":1,"max_ns":2,"count":3}}`), &h); err != nil {
		t.Fatal(err)
	}
	if h.LineQueueHighWater.MaxAt != (QueueHighWaterTimes{}) || h.Save.MaxAt != nil || h.Classification.MaxAt != nil {
		t.Fatal("old maxima acquired fabricated times")
	}
	at := time.Now().UTC()
	h.Save.observe(2, at)
	h.Save.observe(1, at)
	if h.Save.MaxAt != nil {
		t.Fatal("tie or lower value replaced an unknown maximum time")
	}
	h.Save.observe(3, at)
	if h.Save.MaxAt == nil || !h.Save.MaxAt.Equal(at) || h.Save.MaxNS != 3 {
		t.Fatal("higher maximum has no timestamp")
	}
}
