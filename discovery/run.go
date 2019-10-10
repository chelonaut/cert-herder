package discovery

import (
	"context"
	"sync"
	"time"
)

// DiscoveredChainFunc is a type which defines the action to take for each certificate chain found.
type DiscoveredChainFunc func(*DiscoveredChain)

// DiscoveredChain contains all of the data passed to the DiscoveredChainFunc callback.
type DiscoveredChain struct {
	Connection *Connection
	Options    *Options

	// Chain may be empty if no certificate chain was found, or if an error occurred.
	Chain CertificateChain

	// Error may contain details of any error that occurred during discovery. If Error
	// is set then Chain will be nil.
	Error error
}

// Run goes and finds certificates
func Run(options *Options) error {
	// Check the options look sensible
	err := options.Validate()
	if err != nil {
		return err
	}

	// Make a copy so that we can modify it without affecting the caller
	options = options.Clone()

	if options.MaximumParallelConnections < 1 {
		options.MaximumParallelConnections = 1
	}

	// Generate the list of connections to be attempted
	connections, err := options.GetConnections()
	if err != nil {
		return err
	}

	// We limit the rate at which handshakes can be performed with each individual
	// IP address so we don't overload the server.
	rateLimiter := newRateLimiter(5 * time.Second)

	// Create a set of worker goroutines to service a channel of pending connections
	wg := sync.WaitGroup{}
	workChannel := make(chan *Connection, options.MaximumParallelConnections)

	for i := 0; i < options.MaximumParallelConnections; i++ {
		wg.Add(1)

		go func() {
			// Decrement the wait group count when this goroutine ends
			defer wg.Done()

			// Process incoming work on the channel while it's open
			for connection := range workChannel {
				// Rate limit scans of the same IP address
				rateLimiter.waitIfNecessary(connection.IP.String())

				// Discover certificates
				runOneConnection(connection, options)
			}
		}()
	}

	// Send all pending connections into the work channel for processing by the
	// worker goroutines.
	for _, connection := range connections {
		workChannel <- connection
	}

	// Signal that there is no more work by closing the work channel.
	close(workChannel)

	// Wait for all workers to finish
	wg.Wait()

	return nil
}

func runOneConnection(connection *Connection, options *Options) {
	// Create a context to manage the timeout for this connection attempt
	var ctx context.Context
	var cancel context.CancelFunc

	if options.Timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), options.Timeout)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()

	chain, err := connection.GetCertificateChain(ctx, options)
	if err != nil {
		// Pass this error to the callbacks and return
		for _, callback := range options.DiscoveredChainFuncs {
			callback(&DiscoveredChain{
				Connection: connection,
				Options:    options,
				Error:      err,
			})
		}
		return
	}

	// Otherwise pass the chain to the callbacks
	for _, callback := range options.DiscoveredChainFuncs {
		callback(&DiscoveredChain{
			Connection: connection,
			Options:    options,
			Chain:      chain,
		})
	}
}

// rateLimiter attempts to limit how fast scans of the same IP run, so that we don't
// accidentally cause a denial of service attack. Cryptographic operations can be
// very CPU-intensive and this tool tries not to cause harm.
type rateLimiter struct {
	lastConnectTime               map[string]time.Time
	lock                          sync.Mutex
	minDurationBetweenConnections time.Duration

	// For reliable unit testing we allow the wait function to be overridden with
	// a callback so that we can count how many waits occurred and why.
	waitCallback func(key string, duration time.Duration)
}

func newRateLimiter(d time.Duration) *rateLimiter {
	return &rateLimiter{
		lastConnectTime:               map[string]time.Time{},
		minDurationBetweenConnections: d,
		waitCallback:                  defaultWaitCallback,
	}
}

// By default we just sleep but unit tests can override this.
func defaultWaitCallback(key string, duration time.Duration) {
	time.Sleep(duration)
}

func (rl *rateLimiter) waitIfNecessary(key string) {
	now := time.Now()

	rl.lock.Lock()
	lastConnectTime := rl.lastConnectTime[key]

	diff := now.Sub(lastConnectTime)

	if diff >= rl.minDurationBetweenConnections {
		// Enough time has elapsed that we can return without waiting
		// but we must record the last connect as now
		rl.lastConnectTime[key] = now
		rl.lock.Unlock() // unlock before we return

		Debug.Printf("rateLimiter[%v]: lastConnectTime %v, diff %v, no wait needed", key, lastConnectTime, diff)
		return
	}

	// Otherwise we must block the caller for the remaining time
	wakeTime := lastConnectTime.Add(rl.minDurationBetweenConnections)
	sleepDuration := time.Until(wakeTime)
	rl.lastConnectTime[key] = wakeTime
	rl.lock.Unlock() // unlock before we sleep

	Debug.Printf("rateLimiter[%v]: lastConnectTime %v, wakeTime %v, will sleep for %v", key, lastConnectTime, wakeTime, sleepDuration)
	rl.waitCallback(key, sleepDuration)
}
