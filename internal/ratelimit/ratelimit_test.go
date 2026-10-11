package ratelimit

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

// §8: 60 wakes per hour, burst 10.
func TestTokenBucket(t *testing.T) {
	l := New(60.0/3600, 10, 0)
	for i := 0; i < 10; i++ {
		if ok, _ := l.Allow("k", t0); !ok {
			t.Fatalf("wake %d of the burst refused", i+1)
		}
	}
	ok, wait := l.Allow("k", t0)
	if ok || RetryAfterSeconds(wait) != 60 {
		t.Fatalf("11th wake: ok=%v wait=%v", ok, wait)
	}
	if ok, _ := l.Allow("other", t0); !ok {
		t.Fatal("another key shares the bucket")
	}
	// One token a minute; over an hour: the burst and 60 more.
	n := 10
	for s := 1; s <= 3600; s++ {
		if ok, _ := l.Allow("k", t0.Add(time.Duration(s)*time.Second)); ok {
			n++
		}
	}
	if n != 70 {
		t.Fatalf("%d wakes in the first hour, want the burst of 10 and 60", n)
	}
}

func TestPruneAndBound(t *testing.T) {
	l := New(1, 1, 2)
	l.Allow("a", t0)
	l.Allow("b", t0)
	if ok, _ := l.Allow("c", t0); ok {
		t.Fatal("a third key was admitted untracked past the bound")
	}
	if ok, _ := l.Allow("c", t0.Add(2*time.Second)); !ok {
		t.Fatal("refilled buckets were not pruned")
	}
	l.Prune(t0.Add(time.Hour))
	if l.Len() != 0 {
		t.Fatalf("%d idle buckets left", l.Len())
	}
	if RetryAfterSeconds(0) != 1 || RetryAfterSeconds(1500*time.Millisecond) != 2 {
		t.Fatal("retry-after rounding")
	}
}

// §5.2 step 4: a wake within 2 s of the previous one is coalesced.
func TestCoalescer(t *testing.T) {
	c := NewCoalescer(2*time.Second, 0)
	if co, _ := c.Begin("k", t0); co {
		t.Fatal("first wake coalesced")
	}
	if co, _ := c.Begin("k", t0.Add(1999*time.Millisecond)); !co {
		t.Fatal("a wake 1.999 s later was not coalesced")
	}
	if co, _ := c.Begin("other", t0.Add(time.Second)); co {
		t.Fatal("another token coalesced")
	}
	// A coalesced wake is not a send: the window runs from the previous
	// send.
	if co, _ := c.Begin("k", t0.Add(2*time.Second)); co {
		t.Fatal("a wake 2 s after the previous send was coalesced")
	}
	// A failed send is undone: the retry is sent.
	_, undo := c.Begin("f", t0)
	undo()
	if co, _ := c.Begin("f", t0.Add(time.Second)); co {
		t.Fatal("a wake after a failed send was coalesced")
	}
	// Undo restores the previous successful send.
	c2 := NewCoalescer(2*time.Second, 0)
	c2.Begin("k", t0)
	_, undo = c2.Begin("k", t0.Add(3*time.Second))
	undo()
	if co, _ := c2.Begin("k", t0.Add(3500*time.Millisecond)); co {
		t.Fatal("coalesced into a send that failed")
	}
	c.Prune(t0.Add(time.Minute))
	if c.Len() != 0 {
		t.Fatalf("%d entries left after the window", c.Len())
	}
	// A zero window never coalesces.
	z := NewCoalescer(0, 0)
	z.Begin("k", t0)
	if co, _ := z.Begin("k", t0); co {
		t.Fatal("zero window coalesced")
	}
	// A full table does not coalesce new keys, and does not grow.
	f := NewCoalescer(time.Hour, 1)
	f.Begin("a", t0)
	f.Begin("b", t0)
	if co, _ := f.Begin("b", t0); co || f.Len() != 1 {
		t.Fatal("bound not kept")
	}
}
