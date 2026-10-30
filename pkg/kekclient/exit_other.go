//go:build !darwin

package kekclient

import "time"

// awaitExit cannot observe a zombie here without reaping it, so it gives
// the broker the grace period and returns.
func awaitExit(pid int, grace time.Duration) { time.Sleep(grace / 10) }
