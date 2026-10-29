package firewallwatch

import (
	"math"
	"time"
)

// TimingSummary stores nanoseconds and a saturating count, never samples.
type TimingSummary struct {
	LastNS int64      `json:"last_ns"`
	MaxNS  int64      `json:"max_ns"`
	Count  uint64     `json:"count"`
	MaxAt  *time.Time `json:"max_at"`
}

type QueueHighWater struct {
	ALF       int                 `json:"alf"`
	Netfilter int                 `json:"netfilter"`
	MaxAt     QueueHighWaterTimes `json:"max_at"`
}

type QueueHighWaterTimes struct {
	ALF       *time.Time `json:"alf"`
	Netfilter *time.Time `json:"netfilter"`
}

type RunHealth struct {
	LineQueueHighWater   QueueHighWater `json:"line_queue_high_water"`
	ShutdownDroppedLines DroppedLines   `json:"shutdown_dropped_lines"`
	Save                 TimingSummary  `json:"save"`
	Classification       TimingSummary  `json:"classification"`
}

// DroppedLines counts collector lines discarded during run-loop teardown.
type DroppedLines struct {
	ALF       uint64 `json:"alf"`
	Netfilter uint64 `json:"netfilter"`
}

func (c *SourceCoverage) DropLines(n uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.droppedLines = addCount(c.droppedLines, n)
}

func addCount(a, b uint64) uint64 {
	if b > math.MaxUint64-a {
		return math.MaxUint64
	}
	return a + b
}

func addNS(a, b int64) int64 {
	if b > math.MaxInt64-a {
		return math.MaxInt64
	}
	return a + b
}

func (s *TimingSummary) observe(d time.Duration, at time.Time) {
	if d < 0 {
		d = 0
	}
	s.LastNS = int64(d)
	// The first sample is the maximum even when it measures 0 ns; legacy
	// summaries (Count > 0, MaxAt unknown) keep an unknown time.
	if s.LastNS > s.MaxNS || (s.Count == 0 && s.MaxAt == nil) {
		s.MaxNS = s.LastNS
		at = at.UTC()
		s.MaxAt = &at
	}
	s.Count = addCount(s.Count, 1)
}

func (s TimingSummary) valid() bool {
	return s.LastNS >= 0 && s.MaxNS >= s.LastNS && (s.Count != 0 || s.MaxNS == 0)
}

// QueueDepth records the largest observed buffered depth, including a full
// queue before backpressure. It is called only by the feeder for this source.
func (c *SourceCoverage) QueueDepth(n int) {
	c.queueDepthAt(n, time.Now())
}

func (c *SourceCoverage) queueDepthAt(n int, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n > c.queueHighWater {
		c.queueHighWater = n
		at = at.UTC()
		c.queueHighWaterAt = &at
	}
}

func (s *Store) QueueDepth(n int) { s.Coverage("").QueueDepth(n) }

func (s *Store) classify(it Item, classify func(Item) Decision) Decision {
	start := time.Now()
	defer func() { s.State.Health.Classification.observe(time.Since(start), time.Now()) }()
	return classify(it)
}
