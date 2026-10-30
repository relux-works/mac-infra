package firewallwatch

import (
	"sync"
	"time"
)

// wallClock is the watcher's clock for every timestamp it stores: wall time
// that never runs backward. state.json and the journal hold wall times only,
// while time.Now also carries a monotonic reading that time comparisons
// prefer; after the wall clock was set back (this host's time daemon steps it
// by tenths of a second every hour or two) two readings could then be ordered
// one way in memory and the other way on disk, and the reader would refuse
// the state. Readings go through one mutex in call order, so the stored order
// is the order of the calls; during a backward step the clock holds its
// latest value until the wall clock passes it again, at most the step size.
type wallClock struct {
	mu   sync.Mutex
	last time.Time
	held uint64
	// read replaces time.Now in tests.
	read func() time.Time
}

// now returns the current wall time without a monotonic reading, or the
// latest value returned if the wall clock is behind it.
func (c *wallClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Read under the lock, so the order of the values is the order of the
	// readings.
	read := c.read
	if read == nil {
		read = time.Now
	}
	t := read().Round(0)
	if t.Before(c.last) {
		c.held++
		return c.last
	}
	c.last = t
	return t
}

// heldCount is how many readings were held because the wall clock was behind.
func (c *wallClock) heldCount() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.held
}

// now is the store's current time: the run's wall clock while Run runs,
// time.Now otherwise.
func (s *Store) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}
