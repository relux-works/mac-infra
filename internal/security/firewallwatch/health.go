package firewallwatch

import (
	"math"
	"time"
)

// TimingSummary stores nanoseconds and a saturating count, never samples.
type TimingSummary struct {
	LastNS int64  `json:"last_ns"`
	MaxNS  int64  `json:"max_ns"`
	Count  uint64 `json:"count"`
}

type QueueHighWater struct {
	ALF       int `json:"alf"`
	Netfilter int `json:"netfilter"`
}

type RunHealth struct {
	LineQueueHighWater QueueHighWater `json:"line_queue_high_water"`
	Save               TimingSummary  `json:"save"`
	Classification     TimingSummary  `json:"classification"`
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

func (s *TimingSummary) observe(d time.Duration) {
	if d < 0 {
		d = 0
	}
	s.LastNS = int64(d)
	if s.LastNS > s.MaxNS {
		s.MaxNS = s.LastNS
	}
	s.Count = addCount(s.Count, 1)
}

func (s TimingSummary) valid() bool {
	return s.LastNS >= 0 && s.MaxNS >= s.LastNS && (s.Count != 0 || s.MaxNS == 0)
}

// QueueDepth records the largest observed buffered depth, including a full
// queue before backpressure. It is called only by the feeder for this source.
func (c *SourceCoverage) QueueDepth(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n > c.queueHighWater {
		c.queueHighWater = n
	}
}

func (s *Store) QueueDepth(n int) { s.Coverage("").QueueDepth(n) }

func (s *Store) classify(it Item, classify func(Item) Decision) Decision {
	start := time.Now()
	defer func() { s.State.Health.Classification.observe(time.Since(start)) }()
	return classify(it)
}
