package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-vault/vms/pushwire"

	"github.com/vettid/vettid-push/internal/blob"
	"github.com/vettid/vettid-push/internal/nsmtest"
	"github.com/vettid/vettid-push/internal/provider"
)

// The replay cache holds only requests whose key the gateway knows: a
// wake whose blob opened for its signer (§5.2), a registration whose
// attestation verified (§5.1). A signature alone proves nothing (keys
// are free), so a request refused before that point leaves no record.

// replayed returns a request that is sent with identical headers every
// time: the first send's signature (and attestation) again.
func replayed(q rawReq) rawReq {
	var captured http.Header
	q.mangle = func(h http.Header) {
		if captured == nil {
			captured = h.Clone()
			return
		}
		for k, v := range captured {
			h[k] = v
		}
	}
	return q
}

func TestRefusedRequestTakesNoReplaySlot(t *testing.T) {
	g := newGW(t)
	key, wb := g.register(fcmReg)
	otherKey, _ := g.register(apnsReg)
	base := g.srv.replay.Len() // the two registrations and their confirmations
	if base != 4 {
		t.Fatalf("%d records after two registrations", base)
	}
	regBody := fcmReg.Body()
	// A blob that opens for its signer but whose record the gateway
	// would no longer seal (its app has left the channel's list).
	gone, err := g.cfg.Keys.Seal(blob.Record{Platform: "fcm", AppID: "com.example.gone", Token: "t", Key: key.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	strangerDoc, _ := g.nsm.Attest(make([]byte, 32), nil, newKey(t).Public().(ed25519.PublicKey))
	for name, c := range map[string]struct {
		q    rawReq
		code string
	}{
		"wake: a stranger's key, a garbage blob":      {rawReq{path: pushwire.PathWake, body: pushwire.WakeBody("AAAA"), key: newKey(t)}, "blob_invalid"},
		"wake: a stranger's key, a genuine blob":      {rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: newKey(t)}, "blob_invalid"},
		"wake: its own blob, an app no longer listed": {rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(gone), key: key}, "blob_invalid"},
		"wake: its own key, class sync":               {rawReq{path: pushwire.PathWake, body: []byte(`{"wake_blob":"` + wb + `","class":"sync"}`), key: key}, "bad_request"},
		"wake: another vault's key":                   {rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: otherKey}, "blob_invalid"},
		"wake: a stranger's key, not a wake body":     {rawReq{path: pushwire.PathWake, body: []byte(`{}`), key: newKey(t)}, "bad_request"},
		"wake: a stranger, 89 s ahead":                {rawReq{path: pushwire.PathWake, body: pushwire.WakeBody("AAAA"), key: newKey(t), at: t0.Add(89 * time.Second)}, "blob_invalid"},
		"register: no attestation":                    {rawReq{path: pushwire.PathRegister, body: regBody, key: newKey(t), attest: str("")}, "attestation_invalid"},
		"register: not an attestation":                {rawReq{path: pushwire.PathRegister, body: regBody, key: newKey(t), attest: str("AAAA")}, "attestation_invalid"},
		"register: an attestation for another key":    {rawReq{path: pushwire.PathRegister, body: regBody, key: newKey(t), attest: str(nsmtest.Header(strangerDoc))}, "attestation_invalid"},
	} {
		q := replayed(c.q)
		// Twice: the identical request again is refused for the same
		// reason, having left nothing behind the first time.
		for i := 0; i < 2; i++ {
			if a := g.do(q); a.code != c.code {
				t.Errorf("%s: %d %s, want %s", name, a.status, a.body, c.code)
			}
		}
		if n := g.srv.replay.Len(); n != base {
			t.Fatalf("%s: the replay cache holds %d records, want %d", name, n, base)
		}
		// Nor does a refused request's key reach the per-key counts.
		if keys, recs := g.srv.perKey.size(); keys != 2 || recs != 4 {
			t.Fatalf("%s: the per-key counts hold %d keys and %d records, want 2 and 4", name, keys, recs)
		}
	}
	// An accepted request is recorded.
	if a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: key}); a.status != 202 {
		t.Fatalf("wake: %d %s", a.status, a.body)
	}
	if n := g.srv.replay.Len(); n != base+1 {
		t.Fatalf("the replay cache holds %d records after an accepted wake, want %d", n, base+1)
	}
	if g.fcm.count() != 1 {
		t.Errorf("%d sends", g.fcm.count())
	}
}

// A flood of signed requests from strangers, enough to fill the replay
// cache many times over, does not cost a vault its wake or its
// registration.
func TestStrangersCannotFillReplayCache(t *testing.T) {
	// Four records a shard: the three genuine requests below fit
	// whichever shards they fall in.
	const max = 128
	g := newGW(t, func(g *gw) { g.cfg.Limits.ReplayCacheMax, g.cfg.Limits.RegisterPerMinute = max, 1000 })
	key, wb := g.register(fcmReg)
	regBody := fcmReg.Body()
	// Timestamps at the far edge of the freshness window, so that a
	// record, were one written, would live longest.
	ahead := t0.Add(89 * time.Second)
	for i := 0; i < 20*max; i++ {
		if a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody("AAAA"), key: newKey(t), at: ahead}); !a.is(410, "blob_invalid") && !t.Failed() {
			t.Errorf("stranger's wake %d: %d %s", i, a.status, a.body)
		}
	}
	for i := 0; i < max; i++ {
		if a := g.do(rawReq{path: pushwire.PathRegister, body: regBody, key: newKey(t), at: ahead, attest: str("AAAA")}); !a.is(403, "attestation_invalid") && !t.Failed() {
			t.Errorf("stranger's registration %d: %d %s", i, a.status, a.body)
		}
	}
	if n := g.srv.replay.Len(); n != 2 {
		t.Errorf("the replay cache holds %d records, want the one registration and its confirmation", n)
	}
	if a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: key}); a.status != 202 {
		t.Errorf("a vault's wake after the flood: %d %s", a.status, a.body)
	}
	if a := g.do(rawReq{path: pushwire.PathRegister, body: apnsReg.Body(), key: newKey(t)}); a.status != 202 {
		t.Errorf("a vault's registration after the flood: %d %s", a.status, a.body)
	}
	if g.count("rate_limited", "scope", "replay_cache") != 0 {
		t.Error("rate_limited{scope=replay_cache} counted")
	}
	if g.fcm.count() != 1 {
		t.Errorf("%d sends", g.fcm.count())
	}
}

// An accepted request is refused when it comes again, with no second
// effect, for as long as its timestamp is fresh.
func TestReplayOfAcceptedRequestRefused(t *testing.T) {
	g := newGW(t)
	key, wb := g.register(fcmReg)
	q := replayed(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: key})
	if a := g.do(q); a.status != 202 {
		t.Fatalf("wake: %d %s", a.status, a.body)
	}
	for _, d := range []time.Duration{0, 3 * time.Second, 86 * time.Second} {
		g.clk.add(d)
		g.srv.Sweep()
		if a := g.do(q); !a.is(401, "replay_detected") {
			t.Fatalf("replay after %v: %d %s", d, a.status, a.body)
		}
	}
	if g.fcm.count() != 1 {
		t.Fatalf("%d sends for one accepted wake", g.fcm.count())
	}
	// A replayed wake does not use the token's allowance either: the
	// burst of 10 is still there, less the one wake sent.
	for i := 0; i < 9; i++ {
		g.clk.add(3 * time.Second)
		if a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: key}); a.status != 202 {
			t.Fatalf("wake %d after the replays: %d %s", i+2, a.status, a.body)
		}
	}

	g2 := newGW(t)
	regBody := fcmReg.Body()
	r := replayed(rawReq{path: pushwire.PathRegister, body: regBody, key: newKey(t)})
	if a := g2.do(r); a.status != 202 {
		t.Fatalf("register: %d %s", a.status, a.body)
	}
	if a := g2.do(r); !a.is(401, "replay_detected") {
		t.Fatalf("replayed registration: %d %s", a.status, a.body)
	}
	if g2.count("registrations", "platform", "fcm", "outcome", "ok") != 1 {
		t.Error("registrations{outcome=ok} is not 1")
	}
}

// Many copies of one valid request at the same moment: exactly one is
// accepted, by one task (the cache is per process). The check and the
// record are one step under the cache's lock, in
// relayauth.ReplayCache.Check, and nothing a replay must not repeat
// comes before it. This test cannot prove there is no gap between a
// lookup and a record: that rests on Check doing both under its lock.
func TestConcurrentDuplicatesAcceptedOnce(t *testing.T) {
	const copies = 48
	for _, path := range []string{pushwire.PathWake, pushwire.PathRegister} {
		g := newGW(t, func(g *gw) { g.cfg.Limits.RegisterPerMinute = 1000 })
		key, wb := g.register(fcmReg)
		body := pushwire.WakeBody(wb)
		want := http.StatusAccepted
		if path == pushwire.PathRegister {
			body = apnsReg.Body()
			key = newKey(t)
			want = http.StatusAccepted
		}
		h := http.Header{}
		bh := relayauth.BodyHash(body)
		relayauth.SetHeaders(h, key, http.MethodPost, path, g.clk.now(), bh)
		if path == pushwire.PathRegister {
			d := relayauth.Digest(http.MethodPost, path, h.Get(relayauth.HeaderTimestamp), bh)
			doc, err := g.nsm.Attest(d[:], nil, key.Public().(ed25519.PublicKey))
			if err != nil {
				t.Fatal(err)
			}
			h.Set(pushwire.HeaderAttestation, nsmtest.Header(doc))
		}
		before := g.srv.replay.Len()
		type res struct {
			status int
			code   string
			err    error
		}
		out := make([]res, copies)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range out {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req, _ := http.NewRequest(http.MethodPost, g.http.URL+path, bytes.NewReader(body))
				req.Header = h.Clone()
				<-start
				resp, err := g.http.Client().Do(req)
				if err != nil {
					out[i].err = err
					return
				}
				defer resp.Body.Close()
				b, _ := io.ReadAll(resp.Body)
				var e struct {
					Code string `json:"code"`
				}
				_ = json.Unmarshal(b, &e)
				out[i] = res{status: resp.StatusCode, code: e.Code}
			}()
		}
		close(start)
		wg.Wait()
		accepted := 0
		for _, r := range out {
			switch {
			case r.err != nil:
				t.Fatalf("%s: %v", path, r.err)
			case r.status == want:
				accepted++
			case r.status != 401 || r.code != "replay_detected":
				t.Errorf("%s: a duplicate was answered %d %s", path, r.status, r.code)
			}
		}
		if accepted != 1 {
			t.Errorf("%s: %d of %d identical requests accepted, want 1", path, accepted, copies)
		}
		if n := g.srv.replay.Len(); n != before+1 {
			t.Errorf("%s: %d new replay records, want 1", path, n-before)
		}
		if path == pushwire.PathWake && g.fcm.count() != 1 {
			t.Errorf("%d platform sends for one wake", g.fcm.count())
		}
	}
}

// A cache full of records of genuine requests still fails closed: a
// further request is shed with 429, never admitted unrecorded.
func TestFullReplayCacheOfValidRequestsSheds(t *testing.T) {
	const max = 32 // one record a shard
	g := newGW(t, func(g *gw) {
		g.cfg.Limits.ReplayCacheMax, g.cfg.Limits.RegisterPerMinute = max, 1000
		g.cfg.Limits.ChallengeBurst = 1000
	})
	regBody := fcmReg.Body()
	accepted, shed := 0, 0
	for i := 0; i < 8*max; i++ {
		switch a := g.do(rawReq{path: pushwire.PathRegister, body: regBody, key: newKey(t)}); {
		case a.status == 202:
			accepted++
		case a.is(429, "rate_limited") && a.retry == 1:
			shed++
		default:
			t.Fatalf("registration %d: %d %s", i, a.status, a.body)
		}
	}
	// Which shard a request falls in is random, so the exact split is
	// not fixed; every accepted request has its record, though.
	if n := g.srv.replay.Len(); accepted != n || accepted > max || shed < 6*max {
		t.Fatalf("%d accepted, %d shed, %d recorded (capacity %d)", accepted, shed, n, max)
	}
	if g.count("rate_limited", "scope", "replay_cache") != float64(shed) {
		t.Error("rate_limited{scope=replay_cache} does not count the shed requests")
	}
	// The records expire with their timestamps, and requests are
	// admitted again.
	g.clk.add(92 * time.Second)
	if a := g.do(rawReq{path: pushwire.PathRegister, body: regBody, key: newKey(t)}); a.status != 202 {
		t.Fatalf("after expiry: %d %s", a.status, a.body)
	}
}

// A request refused after the replay check is recorded all the same:
// the identical bytes again are replay_detected, and a retry must be
// signed anew. This pins where the check sits: before a registration's
// body is looked at and before a wake's per-token limit.
func TestRefusedAfterReplayCheckIsRecorded(t *testing.T) {
	g := newGW(t, func(g *gw) { g.cfg.Limits.Coalesce = 0 })
	for name, c := range map[string]struct {
		body string
		code string
	}{
		"a body that is not a registration": {`{}`, "bad_request"},
		"an unknown platform":               {`{"platform":"webpush","token":"t","app_id":"a"}`, "platform_invalid"},
		"an app not in the list":            {`{"platform":"fcm","token":"t","app_id":"com.example.other"}`, "app_invalid"},
	} {
		before := g.srv.replay.Len()
		q := replayed(rawReq{path: pushwire.PathRegister, body: []byte(c.body), key: newKey(t)})
		if a := g.do(q); a.code != c.code {
			t.Fatalf("%s: %d %s, want %s", name, a.status, a.body, c.code)
		}
		if a := g.do(q); !a.is(401, "replay_detected") {
			t.Errorf("%s, sent again: %d %s", name, a.status, a.body)
		}
		if n := g.srv.replay.Len(); n != before+1 {
			t.Errorf("%s: %d new records, want 1", name, n-before)
		}
	}
	// A wake refused at the per-token limit.
	key, wb := g.register(fcmReg)
	for i := 0; i < 10; i++ {
		g.clk.add(time.Millisecond)
		if a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: key}); a.status != 202 {
			t.Fatalf("wake %d: %d %s", i+1, a.status, a.body)
		}
	}
	g.clk.add(time.Millisecond)
	q := replayed(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: key})
	if a := g.do(q); !a.is(429, "rate_limited") {
		t.Fatalf("11th wake: %d %s", a.status, a.body)
	}
	if a := g.do(q); !a.is(401, "replay_detected") {
		t.Errorf("11th wake, sent again: %d %s", a.status, a.body)
	}
	// And one the platform refused.
	key2, wb2 := g.register(apnsReg)
	g.apns.set(provider.Result{Outcome: provider.TokenGone})
	q = replayed(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb2), key: key2})
	if a := g.do(q); a.code != "token_gone" {
		t.Fatalf("token_gone: %d %s", a.status, a.body)
	}
	if a := g.do(q); !a.is(401, "replay_detected") {
		t.Errorf("token_gone, sent again: %d %s", a.status, a.body)
	}
	if g.apns.count() != 1 {
		t.Errorf("%d sends", g.apns.count())
	}
}

// Freshness and the replay check use one reading of the clock. A record
// expires a second after its timestamp stops being fresh, so were the
// clock read again for the replay check, a replay arriving at the very
// edge of the window, on a gateway slow enough for a second to pass
// between the two, would be fresh and then find its record expired.
func TestReplayAtEdgeOfWindowWithSlowClock(t *testing.T) {
	g := newGW(t)
	key, wb := g.register(fcmReg)
	g.clk.add(time.Hour)
	at := g.clk.now()
	q := replayed(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: key, at: at})
	if a := g.do(q); a.status != 202 {
		t.Fatalf("wake: %d %s", a.status, a.body)
	}
	// Every reading of the clock is now a second after the one before.
	// Whichever reading freshness is judged by, one of these starts
	// puts it at the last fresh instant.
	for back := 0; back <= 6; back++ {
		g.clk.set(at.Add(relayauth.FreshnessWindow-time.Duration(back)*time.Second), time.Second)
		a := g.do(q)
		if !a.is(401, "replay_detected") && !a.is(401, "timestamp_stale") {
			t.Errorf("replay with the clock %d s before the edge: %d %s", back, a.status, a.body)
		}
	}
	if g.fcm.count() != 1 {
		t.Fatalf("%d sends for one accepted wake", g.fcm.count())
	}
}

// One registered key cannot fill the cache either: it has a cap of live
// records, beyond which its requests alone are refused.
func TestOneKeyCannotFillReplayCache(t *testing.T) {
	g := newGW(t)
	limit := replayPerKey(g.cfg.Limits)
	if limit != 32 || replayPerKey(Limits{TokenPerHour: 600, TokenBurst: 100}) != 2*(100+31+2) {
		t.Fatalf("the cap is %d", limit)
	}
	key, wb := g.register(fcmReg)
	other, otherBlob := g.register(apnsReg)
	const n = 1280
	answers := map[string]int{}
	for i := 0; i < n; i++ {
		g.clk.add(time.Millisecond) // a new timestamp, so a new signature
		a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: key})
		answers[a.code]++
		if a.status != 202 && !a.is(429, "rate_limited") {
			t.Fatalf("wake %d: %d %s", i+1, a.status, a.body)
		}
	}
	// The key's registration, its confirmation and limit-2 wakes are
	// recorded, 10 of them inside the token's burst; the rest are
	// refused untouched.
	atCap := float64(n - (limit - 2))
	if answers[""] != 10 || answers["rate_limited"] != n-10 || g.count("rate_limited", "scope", "key") != atCap ||
		g.count("rate_limited", "scope", "token") != float64(limit-2-10) {
		t.Fatalf("answers %v; at the cap %v, at the token limit %v", answers,
			g.count("rate_limited", "scope", "key"), g.count("rate_limited", "scope", "token"))
	}
	if got := g.srv.replay.Len(); got != limit+2 {
		t.Fatalf("the replay cache holds %d records, want %d for this key and 2 for the other", got, limit)
	}
	if keys, recs := g.srv.perKey.size(); keys != 2 || recs != limit+2 {
		t.Fatalf("the per-key counts hold %d keys and %d records", keys, recs)
	}
	// The answer says when the first of the key's records expires.
	if a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: key}); !a.is(429, "rate_limited") || a.retry < 89 || a.retry > 91 {
		t.Fatalf("at the cap: %d %s", a.status, a.body)
	}
	// Another vault is not affected, and the cache is far from full.
	if a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(otherBlob), key: other}); a.status != 202 {
		t.Fatalf("another vault's wake: %d %s", a.status, a.body)
	}
	if g.count("rate_limited", "scope", "replay_cache") != 0 {
		t.Error("rate_limited{scope=replay_cache} counted")
	}
	// Its records expire and the key is served again.
	g.clk.add(92 * time.Second)
	g.srv.Sweep()
	if keys, recs := g.srv.perKey.size(); keys != 0 || recs != 0 || g.srv.replay.Len() != 0 {
		t.Fatalf("after expiry: %d keys, %d records, %d in the cache", keys, recs, g.srv.replay.Len())
	}
	if a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: key}); a.status != 202 {
		t.Fatalf("after expiry: %d %s", a.status, a.body)
	}
}

// The most a vault can do within its token's limit stays under the cap:
// the registration, the whole burst at once, then for ten minutes every
// wake the limit admits and, each minute, two more that it refuses.
func TestLegitimateBurstStaysUnderKeyCap(t *testing.T) {
	g := newGW(t, func(g *gw) { g.cfg.Limits.Coalesce = 0 })
	key, wb := g.register(fcmReg)
	wake := func() answer {
		g.clk.add(10 * time.Millisecond)
		return g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: key})
	}
	for i := 0; i < 10; i++ {
		if a := wake(); a.status != 202 {
			t.Fatalf("burst wake %d: %d %s", i+1, a.status, a.body)
		}
	}
	for m := 0; m < 10; m++ {
		for i := 0; i < 2; i++ {
			if a := wake(); !a.is(429, "rate_limited") {
				t.Fatalf("minute %d, early wake %d: %d %s", m, i+1, a.status, a.body)
			}
		}
		g.clk.add(time.Minute)
		if a := wake(); a.status != 202 {
			t.Fatalf("minute %d: %d %s", m+1, a.status, a.body)
		}
	}
	if g.count("rate_limited", "scope", "key") != 0 {
		t.Fatal("a vault within its token's limit met the per-key cap")
	}
	if g.fcm.count() != 20 {
		t.Fatalf("%d sends, want 20", g.fcm.count())
	}
}

// A full cache on the wake path: shed with 429, never admitted
// unrecorded, and nothing is sent for a shed wake.
func TestFullReplayCacheShedsWakes(t *testing.T) {
	const max = 32 // one record a shard
	g := newGW(t, func(g *gw) {
		g.cfg.Limits.ReplayCacheMax, g.cfg.Limits.Coalesce = max, 0
		// Limits high enough that only the cache refuses.
		g.cfg.Limits.TokenPerHour, g.cfg.Limits.TokenBurst = 360000, 100000
	})
	key, wb := g.register(fcmReg)
	// The registration's record expires. Sweep it out: an expired
	// record otherwise stays in its shard, and in Len, until a request
	// happens to fall in that shard.
	g.clk.add(92 * time.Second)
	g.srv.Sweep()
	if n := g.srv.replay.Len(); n != 0 {
		t.Fatalf("%d records after the sweep", n)
	}
	const n = 8 * max
	accepted, shed := 0, 0
	for i := 0; i < n; i++ {
		g.clk.add(time.Millisecond)
		switch a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: key}); {
		case a.status == 202:
			accepted++
		case a.is(429, "rate_limited") && a.retry == 1:
			shed++
		default:
			t.Fatalf("wake %d: %d %s", i+1, a.status, a.body)
		}
	}
	if got := g.srv.replay.Len(); accepted != got || accepted > max || shed < 6*max || accepted+shed != n {
		t.Fatalf("%d accepted, %d shed, %d recorded (capacity %d)", accepted, shed, got, max)
	}
	if g.fcm.count() != accepted {
		t.Fatalf("%d sends for %d accepted wakes", g.fcm.count(), accepted)
	}
	if g.count("rate_limited", "scope", "replay_cache") != float64(shed) || g.count("rate_limited", "scope", "key") != 0 {
		t.Error("rate_limited{scope=replay_cache} does not count the shed wakes")
	}
	if _, recs := g.srv.perKey.size(); recs != accepted {
		t.Errorf("the per-key counts hold %d records for %d accepted wakes", recs, accepted)
	}
}

// A key at its cap is told when the FIRST of its records expires, which
// is when it will be served again, not the last.
func TestKeyCapRetryAfterIsFirstExpiry(t *testing.T) {
	g := newGW(t, func(g *gw) { g.cfg.Limits.Coalesce = 0 })
	limit := replayPerKey(g.cfg.Limits)
	key := newKey(t)
	pending := g.registerPending(key, fcmReg) // a record that expires 91 s from now
	g.clk.add(2 * time.Second)
	c := g.confirm(key, pending, g.code(fcmReg))
	wb, err := pushwire.ParseRegistered([]byte(c.body))
	if err != nil {
		t.Fatalf("confirm: %d %s", c.status, c.body)
	}
	wake := func() answer {
		return g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: key})
	}
	// The other limit-1 records (the confirmation and the wakes), two
	// seconds apart: 62 s in all.
	for i := 2; i < limit; i++ {
		g.clk.add(2 * time.Second)
		if a := wake(); a.status != 202 && !a.is(429, "rate_limited") {
			t.Fatalf("wake %d: %d %s", i, a.status, a.body)
		}
	}
	if g.count("rate_limited", "scope", "key") != 0 {
		t.Fatal("the cap was met early")
	}
	// At the cap. The registration's record has 91 - 62 = 29 s left,
	// the newest wake's 91 s.
	a := wake()
	if !a.is(429, "rate_limited") || a.retry != 29 || a.header.Get("Retry-After") != "29" || g.count("rate_limited", "scope", "key") != 1 {
		t.Fatalf("at the cap: %d %s", a.status, a.body)
	}
	// Just before that record expires the key is still refused; once
	// it has, one request is admitted and the key is at its cap again,
	// now waiting for the confirmation's record (2 s later).
	g.clk.add(29*time.Second - time.Millisecond)
	if a := wake(); !a.is(429, "rate_limited") || a.retry != 1 || g.count("rate_limited", "scope", "key") != 2 {
		t.Fatalf("a millisecond early: %d %s", a.status, a.body)
	}
	g.clk.add(time.Millisecond)
	wake()
	if g.count("rate_limited", "scope", "key") != 2 {
		t.Fatal("still refused at the cap once the first record had expired")
	}
	if a := wake(); !a.is(429, "rate_limited") || a.retry != 2 || g.count("rate_limited", "scope", "key") != 3 {
		t.Fatalf("at the cap again: %d %s", a.status, a.body)
	}
}
