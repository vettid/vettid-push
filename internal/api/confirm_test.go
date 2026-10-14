package api

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/pushwire"

	"github.com/vettid/vettid-push/internal/blob"
	"github.com/vettid/vettid-push/internal/provider"
)

// §5.1: a vault that does not hold the push token's phone gets no wake
// blob for it. A member's genuine vault registers a token it learned:
// the code goes to the token's phone, the pending registration does not
// wake, and no guess confirms it.
func TestBlobOnlyForTokenHolder(t *testing.T) {
	g := newGW(t)
	key := newKey(t)
	pending := g.registerPending(key, fcmReg)
	// The pending registration is no wake blob.
	if a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(pending), key: key}); !a.is(410, "blob_invalid") {
		t.Fatalf("wake with a pending registration: %d %s", a.status, a.body)
	}
	for _, guess := range []string{"AAAAAAAAAAAAAAAAAAAAAA", strings.Repeat("A", 64), "x"} {
		g.clk.add(time.Second)
		if a := g.confirm(key, pending, guess); !a.is(403, "challenge_invalid") {
			t.Fatalf("guess %q: %d %s", guess, a.status, a.body)
		}
	}
	if g.fcm.count() != 0 {
		t.Fatal("a wake was sent")
	}
	if g.count("confirmations", "platform", "unknown", "outcome", "challenge_invalid") != 3 {
		t.Error("confirmations{outcome=challenge_invalid}")
	}
	// The phone's code works, once.
	g.clk.add(time.Second)
	if a := g.confirm(key, pending, g.code(fcmReg)); a.status != 201 {
		t.Fatalf("the phone's code: %d %s", a.status, a.body)
	}
}

// §5.1: every refused confirmation is the same 403 challenge_invalid (no
// oracle), and leaves no replay record.
func TestConfirmRefusals(t *testing.T) {
	g := newGW(t)
	key := newKey(t)
	pending := g.registerPending(key, fcmReg)
	code := g.code(fcmReg)
	_, wb := g.register(apnsReg)
	otherPending := g.registerPending(newKey(t), apnsReg)
	base := g.srv.replay.Len()
	var bodies []string
	for name, q := range map[string]rawReq{
		"another signer":            {path: PathConfirm, body: confirmBody(pending, code), key: newKey(t)},
		"another vault's pending":   {path: PathConfirm, body: confirmBody(otherPending, code), key: key},
		"a wake blob as pending":    {path: PathConfirm, body: confirmBody(wb, code), key: key},
		"garbage pending":           {path: PathConfirm, body: confirmBody("AAAA", code), key: key},
		"another registration code": {path: PathConfirm, body: confirmBody(pending, g.code(apnsReg)), key: key},
	} {
		a := g.do(q)
		if !a.is(403, "challenge_invalid") {
			t.Errorf("%s: %d %s", name, a.status, a.body)
		}
		bodies = append(bodies, a.body)
	}
	for _, b := range bodies {
		if b != bodies[0] {
			t.Fatalf("answers differ: %s / %s", b, bodies[0])
		}
	}
	if n := g.srv.replay.Len(); n != base {
		t.Fatalf("refused confirmations left %d replay records", n-base)
	}
	// Bodies that are not a confirmation.
	for _, body := range []string{`{}`, `{"pending":"` + pending + `"}`, `{"code":"` + code + `"}`,
		`{"pending":"` + pending + `","code":"` + code + `","x":1}`,
		`{"pending":"` + pending + `","code":"` + code + `","code":"` + code + `"}`,
		`{"pending":"` + pending + `","code":7}`, `{"pending":null,"code":"` + code + `"}`,
		`{"pending":"` + pending + `","code":"` + code + `"} {}`, `{"pending":"` + pending + `","code":""}`, `[]`} {
		if a := g.do(rawReq{path: PathConfirm, body: []byte(body), key: key}); !a.is(400, "bad_request") {
			t.Errorf("body %.60s: %d %s", body, a.status, a.body)
		}
	}
	// Unsigned and stale requests are refused before anything else.
	if a := g.do(rawReq{path: PathConfirm, body: confirmBody(pending, code)}); !a.is(401, "signature_invalid") {
		t.Errorf("unsigned: %d %s", a.status, a.body)
	}
	if a := g.do(rawReq{path: PathConfirm, body: confirmBody(pending, code), key: key, at: g.clk.now().Add(-91 * time.Second)}); !a.is(401, "timestamp_stale") {
		t.Errorf("stale: %d %s", a.status, a.body)
	}
	// The right one is accepted, and the same signed request again is
	// a replay.
	q := replayed(rawReq{path: PathConfirm, body: confirmBody(pending, code), key: key})
	if a := g.do(q); a.status != 201 {
		t.Fatalf("confirm: %d %s", a.status, a.body)
	}
	if a := g.do(q); !a.is(401, "replay_detected") {
		t.Fatalf("replayed confirmation: %d %s", a.status, a.body)
	}
}

// §5.1: the challenge is valid for 10 minutes; a record the gateway
// would no longer seal is not confirmed.
func TestConfirmLifetimeAndChannelRules(t *testing.T) {
	g := newGW(t)
	k1 := newKey(t)
	p1 := g.registerPending(k1, fcmReg)
	c1 := g.code(fcmReg)
	g.clk.add(provider.ChallengeLife + time.Second)
	if a := g.confirm(k1, p1, c1); !a.is(403, "challenge_invalid") {
		t.Fatalf("after 10 minutes: %d %s", a.status, a.body)
	}
	k3 := newKey(t)
	p3 := g.registerPending(k3, fcmReg)
	g.clk.add(provider.ChallengeLife)
	if a := g.confirm(k3, p3, g.code(fcmReg)); a.status != 201 {
		t.Fatalf("at 10 minutes: %d %s", a.status, a.body)
	}
	// The platform is withdrawn between the two steps (a restart with
	// another PUSH_PLATFORMS).
	k4 := newKey(t)
	p4 := g.registerPending(k4, apnsReg)
	c4 := g.code(apnsReg)
	delete(g.cfg.Providers, provider.APNs)
	g.rebuild()
	if a := g.confirm(k4, p4, c4); !a.is(403, "challenge_invalid") {
		t.Fatalf("a platform withdrawn: %d %s", a.status, a.body)
	}
}

// §5.1, §7: the challenge's send is answered as a wake's would be, and
// no pending registration is handed out when it fails.
func TestRegisterChallengeSendFailures(t *testing.T) {
	g := newGW(t)
	for _, c := range []struct {
		res    provider.Result
		status int
		code   string
	}{
		{provider.Result{Outcome: provider.TokenGone, Detail: "UNREGISTERED"}, 410, "token_gone"},
		{provider.Result{Outcome: provider.TokenInvalid, Detail: "INVALID_ARGUMENT"}, 400, "token_invalid"},
		{provider.Result{Outcome: provider.RateLimited, RetryAfter: 30}, 429, "rate_limited"},
		{provider.Result{Outcome: provider.Unavailable, Detail: "UNAVAILABLE"}, 502, "provider_unavailable"},
		{provider.Result{Outcome: provider.AuthFailed, Detail: "UNAUTHENTICATED"}, 502, "provider_unavailable"},
	} {
		g.fcm.setChal(c.res)
		g.clk.add(3 * time.Second)
		a := g.do(rawReq{path: pushwire.PathRegister, body: fcmReg.Body(), key: newKey(t)})
		if !a.is(c.status, c.code) || strings.Contains(a.body, "pending") {
			t.Errorf("%v: %d %s", c.res.Outcome, a.status, a.body)
		}
		if g.count("challenges", "platform", "fcm", "outcome", c.res.Outcome.String()) != 1 {
			t.Errorf("challenges{outcome=%s}", c.res.Outcome)
		}
	}
	if g.count("registrations", "platform", "fcm", "outcome", "token_gone") != 1 {
		t.Error("registrations{outcome=token_gone}")
	}
	if !strings.Contains(g.logs.String(), "platform send failed") {
		t.Error("an unavailable platform at registration is not logged")
	}
	if g.fcm.count() != 0 {
		t.Error("a wake was sent")
	}
}

// §8: challenges to one token are limited apart from its wakes: a
// registration beyond the limit is refused before anything is sent, and
// the token's wakes are not affected.
func TestChallengeLimit(t *testing.T) {
	g := newGW(t, func(g *gw) { g.cfg.Limits = DefaultLimits() })
	key, wb := g.register(fcmReg)
	for i := 1; i < 5; i++ {
		g.clk.add(time.Second)
		g.registerPending(newKey(t), fcmReg)
	}
	g.clk.add(time.Second)
	a := g.do(rawReq{path: pushwire.PathRegister, body: fcmReg.Body(), key: newKey(t)})
	if !a.is(429, "rate_limited") || a.retry < 300 || a.retry > 360 || g.count("rate_limited", "scope", "challenge") != 1 {
		t.Fatalf("sixth challenge: %d %s", a.status, a.body)
	}
	if g.fcm.chalCount() != 5 {
		t.Fatalf("%d challenges sent", g.fcm.chalCount())
	}
	// Another token is not affected, nor this token's wakes.
	g.registerPending(newKey(t), apnsReg)
	if a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: key}); a.status != 202 {
		t.Fatalf("wake: %d %s", a.status, a.body)
	}
	// Six minutes refill one.
	g.clk.add(6 * time.Minute)
	g.registerPending(newKey(t), fcmReg)
}

// §4: a blob is honoured for 90 days from its issue; then it is
// blob_invalid like any other, counted apart. A reseal keeps the issue
// time, so it does not extend the age.
func TestBlobMaxAge(t *testing.T) {
	g := newGW(t)
	key, wb := g.register(fcmReg)
	issued := g.clk.now()
	if BlobMaxAge != 90*24*time.Hour {
		t.Fatal("BlobMaxAge changed")
	}
	// A key rotation: the next wake is answered with a reseal.
	rotated, err := blob.RotateSecret(g.secret)
	if err != nil {
		t.Fatal(err)
	}
	g.secret = rotated
	g.rebuild()
	g.clk.set(issued.Add(BlobMaxAge-time.Hour), 0)
	reseal, err := g.vault().Wake(t.Context(), key, wb)
	if err != nil || reseal == "" {
		t.Fatalf("wake within the age: %q %v", reseal, err)
	}
	rec, current, err := g.cfg.Keys.Open(reseal)
	if err != nil || !current || rec.Issued != issued.Unix() {
		t.Fatalf("the reseal's issue time %d, want %d", rec.Issued, issued.Unix())
	}
	g.clk.set(issued.Add(BlobMaxAge), 0)
	if _, err := g.vault().Wake(t.Context(), key, reseal); err != nil {
		t.Fatalf("at the age: %v", err)
	}
	garbage := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody("AAAA"), key: key})
	for _, b := range []string{wb, reseal} {
		g.clk.set(issued.Add(BlobMaxAge+time.Second), 0)
		a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(b), key: key})
		if !a.is(410, "blob_invalid") || a.body != garbage.body {
			t.Fatalf("past the age: %d %s", a.status, a.body)
		}
		g.clk.add(time.Second)
	}
	if g.count("blob_expired") != 2 {
		t.Fatalf("blob_expired %v", g.count("blob_expired"))
	}
	if !bytes.Equal(rec.Key, key.Public().(ed25519.PublicKey)) {
		t.Fatal("record key")
	}
}
