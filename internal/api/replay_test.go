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

	"github.com/vettid/vettid-push/internal/nsmtest"
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
	base := g.srv.replay.Len() // the two registrations
	if base != 2 {
		t.Fatalf("%d records after two registrations", base)
	}
	regBody := fcmReg.Body()
	strangerDoc, _ := g.nsm.Attest(make([]byte, 32), nil, newKey(t).Public().(ed25519.PublicKey))
	for name, c := range map[string]struct {
		q    rawReq
		code string
	}{
		"wake: a stranger's key, a garbage blob":   {rawReq{path: pushwire.PathWake, body: pushwire.WakeBody("AAAA"), key: newKey(t)}, "blob_invalid"},
		"wake: a stranger's key, a genuine blob":   {rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: newKey(t)}, "blob_invalid"},
		"wake: another vault's key":                {rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: otherKey}, "blob_invalid"},
		"wake: a stranger's key, not a wake body":  {rawReq{path: pushwire.PathWake, body: []byte(`{}`), key: newKey(t)}, "bad_request"},
		"wake: a stranger, 89 s ahead":             {rawReq{path: pushwire.PathWake, body: pushwire.WakeBody("AAAA"), key: newKey(t), at: t0.Add(89 * time.Second)}, "blob_invalid"},
		"register: no attestation":                 {rawReq{path: pushwire.PathRegister, body: regBody, key: newKey(t), attest: str("")}, "attestation_invalid"},
		"register: not an attestation":             {rawReq{path: pushwire.PathRegister, body: regBody, key: newKey(t), attest: str("AAAA")}, "attestation_invalid"},
		"register: an attestation for another key": {rawReq{path: pushwire.PathRegister, body: regBody, key: newKey(t), attest: str(nsmtest.Header(strangerDoc))}, "attestation_invalid"},
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
	const max = 64 // two records a shard
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
	if n := g.srv.replay.Len(); n != 1 {
		t.Errorf("the replay cache holds %d records, want the one registration", n)
	}
	if a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: key}); a.status != 202 {
		t.Errorf("a vault's wake after the flood: %d %s", a.status, a.body)
	}
	if _, err := g.vault().Register(t.Context(), newKey(t), apnsReg); err != nil {
		t.Errorf("a vault's registration after the flood: %v", err)
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
	if a := g2.do(r); a.status != 201 {
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
// accepted. The check and the record are one step under the cache's
// lock, and nothing with an effect comes before it.
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
			want = http.StatusCreated
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
	g := newGW(t, func(g *gw) { g.cfg.Limits.ReplayCacheMax, g.cfg.Limits.RegisterPerMinute = max, 1000 })
	regBody := fcmReg.Body()
	accepted, shed := 0, 0
	for i := 0; i < 8*max; i++ {
		switch a := g.do(rawReq{path: pushwire.PathRegister, body: regBody, key: newKey(t)}); {
		case a.status == 201:
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
	if a := g.do(rawReq{path: pushwire.PathRegister, body: regBody, key: newKey(t)}); a.status != 201 {
		t.Fatalf("after expiry: %d %s", a.status, a.body)
	}
}
