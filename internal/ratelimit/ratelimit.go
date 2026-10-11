// Package ratelimit provides an in-memory, keyed token-bucket limiter and
// the wake coalescer (PUSH-GATEWAY §8, §5.2 step 4). It is the relay's
// limiter (vettid-relay internal/ratelimit).
//
// Keys are a source address (an IPv4 address or an IPv6 /64) or an HMAC of
// a push token under a per-process random key; they live in memory only
// and are never logged or persisted.
package ratelimit

import (
	"math"
	"sync"
	"time"
)

// Limiter is a set of token buckets keyed by string. Memory is bounded by
// MaxKeys: idle (full) buckets are dropped, and when the table is full of
// active buckets new keys are refused rather than admitted untracked.
type Limiter struct {
	rate    float64 // tokens per second
	burst   float64
	maxKeys int

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a limiter allowing rate events/second with the given burst.
func New(rate float64, burst int, maxKeys int) *Limiter {
	if maxKeys <= 0 {
		maxKeys = 100_000
	}
	return &Limiter{rate: rate, burst: float64(burst), maxKeys: maxKeys, buckets: map[string]*bucket{}}
}

// Allow consumes one token for key. When refused it returns the wait until
// a token is available (at least one second).
func (l *Limiter) Allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			l.pruneLocked(now)
			if len(l.buckets) >= l.maxKeys {
				return false, time.Second
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = math.Min(l.burst, b.tokens+el*l.rate)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	if wait < time.Second {
		wait = time.Second
	}
	return false, wait
}

// pruneLocked drops buckets that have refilled completely (indistinguishable
// from a fresh bucket).
func (l *Limiter) pruneLocked(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}

// Prune drops idle buckets; run periodically.
func (l *Limiter) Prune(now time.Time) {
	l.mu.Lock()
	l.pruneLocked(now)
	l.mu.Unlock()
}

// Len returns the number of tracked keys.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// RetryAfterSeconds converts a wait to the integer seconds used in
// Retry-After / retry_after (minimum 1).
func RetryAfterSeconds(d time.Duration) int {
	s := int(math.Ceil(d.Seconds()))
	if s < 1 {
		s = 1
	}
	return s
}

// Coalescer remembers, per key, when the last wake was sent, so that a
// wake within the window of the previous one is answered without a second
// platform send (PUSH-GATEWAY §5.2 step 4). Memory is bounded by maxKeys;
// when the table is full of live entries a new key is simply not
// coalesced.
type Coalescer struct {
	window  time.Duration
	maxKeys int

	mu   sync.Mutex
	last map[string]time.Time
}

// NewCoalescer returns a coalescer; a window of zero or less never
// coalesces.
func NewCoalescer(window time.Duration, maxKeys int) *Coalescer {
	if maxKeys <= 0 {
		maxKeys = 100_000
	}
	return &Coalescer{window: window, maxKeys: maxKeys, last: map[string]time.Time{}}
}

// Begin reports whether a wake for key at now is coalesced into the
// previous one. If not, it records now as the key's last wake and returns
// an undo function, to be called if the send then fails: a failed send is
// not a wake to coalesce into.
func (c *Coalescer) Begin(key string, now time.Time) (coalesced bool, undo func()) {
	if c.window <= 0 {
		return false, func() {}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	prev, had := c.last[key]
	if had && now.Sub(prev) < c.window && !now.Before(prev) {
		return true, func() {}
	}
	if !had && len(c.last) >= c.maxKeys {
		c.pruneLocked(now)
		if len(c.last) >= c.maxKeys {
			return false, func() {}
		}
	}
	c.last[key] = now
	return false, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if t, ok := c.last[key]; ok && t.Equal(now) {
			if had {
				c.last[key] = prev
			} else {
				delete(c.last, key)
			}
		}
	}
}

func (c *Coalescer) pruneLocked(now time.Time) {
	for k, t := range c.last {
		if now.Sub(t) >= c.window {
			delete(c.last, k)
		}
	}
}

// Prune drops entries older than the window; run periodically.
func (c *Coalescer) Prune(now time.Time) {
	c.mu.Lock()
	c.pruneLocked(now)
	c.mu.Unlock()
}

// Len returns the number of tracked keys.
func (c *Coalescer) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.last)
}
