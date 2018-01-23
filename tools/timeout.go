package tools

import (
	"time"
)

const DEFAULT_TIMEOUT_DURATION = 20 * time.Second

// Timeout waits for "dur" delay to expire, and then writes in "c"
func Timeout(dur time.Duration, c chan<- bool) {
	time.Sleep(dur)
	c <- true
}

// StartTimeout initiates a goroutine that will write a boolean into the returned channel after the "dur" delay expired.
func StartTimeout(dur time.Duration) <-chan bool {
	c := make(chan bool, 1)
	go Timeout(dur, c)
	return c
}
