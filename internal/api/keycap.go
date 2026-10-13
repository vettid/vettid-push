package api

import (
	"sync"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
)

// replayRecordLife is the longest a replay record can live: a timestamp
// the freshness window ahead of the clock, kept until it is the window
// (and a second) behind it.
const replayRecordLife = 2*relayauth.FreshnessWindow + time.Second

// minReplayPerKey is the least the per-key cap is ever set to.
const minReplayPerKey = 32

// replayPerKey is the number of live replay records one key may have
// (§8). A key belongs to one registration and so to one push token
// (§3), and the per-token limit admits at most TokenBurst wakes plus
// the bucket's refill during one record's life: 10 + 4 with the
// defaults. Every wake beyond that is refused at the token limit
// whatever the vault does, so with the key's one registration that is
// all the records a vault can put to use; the cap is twice that, for
// retries signed anew and a clock that is off, and never under 32.
func replayPerKey(l Limits) int {
	refill := (l.TokenPerHour*int(replayRecordLife/time.Second) + 3599) / 3600
	if n := 2 * (l.TokenBurst + refill + 1); n > minReplayPerKey {
		return n
	}
	return minReplayPerKey
}

// keyRecords counts each key's live replay records, so that one key
// cannot fill the replay cache for everyone. It holds one expiry per
// record the replay cache accepted and nothing else: its size is
// bounded by the replay cache's, and a key enters it only with a
// record, that is after the check that binds the key to a registration.
// A stranger's key never reaches it.
type keyRecords struct {
	mu  sync.Mutex
	max int
	m   map[[32]byte][]int64 // key → unix-nano expiries of its records
}

func newKeyRecords(max int) *keyRecords {
	return &keyRecords{max: max, m: map[[32]byte][]int64{}}
}

func live(exp []int64, now int64) []int64 {
	out := exp[:0]
	for _, e := range exp {
		if e > now {
			out = append(out, e)
		}
	}
	return out
}

// record runs check, the replay cache's check-and-record, unless key
// already has its cap of live records; then it reports false and the
// time until the first of them expires. The count and the check are one
// step under the lock, so concurrent requests cannot pass the cap.
func (k *keyRecords) record(key []byte, exp, now time.Time, check func() error) (ok bool, wait time.Duration, err error) {
	var id [32]byte
	copy(id[:], key)
	n := now.UnixNano()
	k.mu.Lock()
	defer k.mu.Unlock()
	l := live(k.m[id], n)
	defer func() {
		if len(l) == 0 {
			delete(k.m, id)
		} else {
			k.m[id] = l
		}
	}()
	if len(l) >= k.max {
		first := l[0]
		for _, e := range l {
			first = min(first, e)
		}
		return false, time.Duration(first - n), nil
	}
	if err := check(); err != nil {
		return true, 0, err
	}
	l = append(l, exp.UnixNano())
	return true, 0, nil
}

// sweep drops expired entries and keys left with none.
func (k *keyRecords) sweep(now time.Time) {
	n := now.UnixNano()
	k.mu.Lock()
	defer k.mu.Unlock()
	for id, exp := range k.m {
		if l := live(exp, n); len(l) == 0 {
			delete(k.m, id)
		} else {
			k.m[id] = l
		}
	}
}

// size returns the number of keys and of expiries held.
func (k *keyRecords) size() (keys, records int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, exp := range k.m {
		records += len(exp)
	}
	return len(k.m), records
}
