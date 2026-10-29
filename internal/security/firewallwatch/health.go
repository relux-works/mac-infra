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
	// Maintenance times the nettop tick's backend health check, including an
	// Init after a failed check.
	Maintenance TimingSummary `json:"maintenance"`
	// SlowOps keeps the newest SlowOpLimit operations that took at least
	// SlowOpThreshold, in completion order. SlowOpsDroppedThrough is the
	// latest completion time among records the bound dropped.
	SlowOps               []SlowOp   `json:"slow_ops"`
	SlowOpsDroppedThrough *time.Time `json:"slow_ops_dropped_through"`
	// Journal times state-journal appends, heartbeats included.
	// JournalTornTail counts journals found with a torn last line at open.
	Journal         TimingSummary `json:"journal"`
	JournalTornTail uint64        `json:"journal_torn_tail"`
}

// The slow-operation record keeps run-loop operations of at least two seconds,
// the newest 512 (BUG-261029-kpyw8s).
const (
	SlowOpThreshold = 2 * time.Second
	SlowOpLimit     = 512
)

// Slow-operation kinds.
const (
	SlowSave           = "save"
	SlowClassification = "classification"
	SlowMaintenance    = "maintenance"
	SlowNettopSample   = "nettop_sample"
	SlowJournal        = "journal"
)

// slowOpThreshold is SlowOpThreshold; tests lower it.
var slowOpThreshold = SlowOpThreshold

// SlowOp is metadata about one slow run-loop operation: no item text, hosts,
// apps or paths. At is its completion time. Items counts the nettop rows of a
// sample and the labelled pool rows of a maintenance whose Init succeeded.
type SlowOp struct {
	Kind  string    `json:"kind"`
	At    time.Time `json:"at"`
	NS    int64     `json:"duration_ns"`
	Items int       `json:"items,omitempty"`
}

func slowKind(kind string) bool {
	return kind == SlowSave || kind == SlowClassification || kind == SlowMaintenance || kind == SlowNettopSample || kind == SlowJournal
}

// recordSlow keeps an operation of at least slowOpThreshold, dropping the
// oldest record beyond SlowOpLimit.
func (h *RunHealth) recordSlow(kind string, d time.Duration, at time.Time, items int) {
	if d < slowOpThreshold {
		return
	}
	if len(h.SlowOps) >= SlowOpLimit {
		dropped := h.SlowOps[0].At
		if h.SlowOpsDroppedThrough == nil || dropped.After(*h.SlowOpsDroppedThrough) {
			h.SlowOpsDroppedThrough = &dropped
		}
		h.SlowOps = append(h.SlowOps[:0], h.SlowOps[1:]...)
	}
	h.SlowOps = append(h.SlowOps, SlowOp{Kind: kind, At: at.UTC(), NS: int64(d), Items: items})
}

func (h RunHealth) slowOpsValid() bool {
	if len(h.SlowOps) > SlowOpLimit {
		return false
	}
	for _, op := range h.SlowOps {
		if !slowKind(op.Kind) || op.At.IsZero() || op.NS < 0 || op.Items < 0 {
			return false
		}
	}
	return true
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
	defer func() {
		d, now := time.Since(start), time.Now()
		s.State.Health.Classification.observe(d, now)
		s.State.Health.recordSlow(SlowClassification, d, now, 0)
	}()
	return classify(it)
}
