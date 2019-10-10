package discovery

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRateLimiterNonBlocking(t *testing.T) {
	limit := 10 * time.Second
	r := newRateLimiter(limit)

	waitCount := 0
	r.waitCallback = func(key string, duration time.Duration) {
		waitCount++
	}

	// These are all unique and should not block
	r.waitIfNecessary("10.1.2.3")
	r.waitIfNecessary("10.1.2.4")
	r.waitIfNecessary("10.1.2.5")

	// Ensure the wait callback wasn't called
	require.Zero(t, waitCount, "The wait callback must not be called")
}

func TestRateLimiterBlocking(t *testing.T) {
	// We need a limit which is long enough to be reasonably measurable on a
	// modern system without causing false positives due to scheduling jitter.
	// Times in the order of hundreds of milliseconds should be large enough
	// not to be subject to jitter but not so long as to slow the unit tests
	// too much.
	limit := 100 * time.Millisecond
	r := newRateLimiter(limit)

	waitCount := 0
	waitCountByKey := make(map[string]int)
	var waitCallbackError error
	r.waitCallback = func(key string, duration time.Duration) {
		waitCount++

		if key != "10.1.2.1" && key != "10.1.2.3" {
			waitCallbackError = fmt.Errorf("Wait callback incorrectly called for key '%v'", key)
		}

		waitCountByKey[key]++
	}

	// We should block 4 times (the first call for each IP is free)
	r.waitIfNecessary("10.1.2.1") // first call for 10.1.2.1 shouldn't block
	r.waitIfNecessary("10.1.2.3") // first call for 10.1.2.3 shouldn't block
	r.waitIfNecessary("10.1.2.3") // repeat call for 10.1.2.3 call should block (first wait)
	r.waitIfNecessary("10.1.2.3") // repeat call for 10.1.2.3 should block (second wait)
	r.waitIfNecessary("10.1.2.3") // repeat call for 10.1.2.3 should block (third wait)
	r.waitIfNecessary("10.1.2.3") // repeat call for 10.1.2.3 should block (fourth wait)
	r.waitIfNecessary("10.1.2.5") // first call for 10.1.2.5 shouldn't block
	r.waitIfNecessary("10.1.2.1") // repeat call for 10.1.2.1 call should block (fifth wait)

	require.Equal(t, 5, waitCount, "Incorrect number of wait callbacks invoked")
	require.NoError(t, waitCallbackError, "Unexpected error occurred in wait callback: %v", waitCallbackError)
	require.Equal(t, 4, waitCountByKey["10.1.2.3"], "Incorrect number of waits for key 10.1.2.3")
	require.Equal(t, 1, waitCountByKey["10.1.2.1"], "Incorrect number of waits for key 10.1.2.1")
}
