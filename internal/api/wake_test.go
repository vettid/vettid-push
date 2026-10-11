package api

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/pushwire"

	"github.com/vettid/vettid-push/internal/blob"
	"github.com/vettid/vettid-push/internal/provider"
)

func gwErr(err error) *pushwire.Error {
	var ge *pushwire.Error
	errors.As(err, &ge)
	return ge
}

// §5.2 with the vault's own client: a wake opens the blob and hands the
// platform client the registration, nothing more; the answer is 202 {}.
func TestWake(t *testing.T) {
	g := newGW(t)
	ctx := context.Background()
	fk, fb := g.register(fcmReg)
	ak, ab := g.register(apnsReg)
	sandbox := apnsReg
	sandbox.Environment = "sandbox"
	sk, sb := g.register(sandbox)

	if reseal, err := g.vault().Wake(ctx, fk, fb); err != nil || reseal != "" {
		t.Fatalf("fcm wake: reseal %q err %v", reseal, err)
	}
	if _, err := g.vault().Wake(ctx, ak, ab); err != nil {
		t.Fatalf("apns wake: %v", err)
	}
	if g.fcm.count() != 1 || g.fcm.sent[0] != (provider.Message{Platform: "fcm", AppID: fcmReg.AppID, Token: fcmReg.Token}) {
		t.Fatalf("fcm got %+v", g.fcm.sent)
	}
	if g.apns.count() != 1 || g.apns.sent[0] != (provider.Message{Platform: "apns", Environment: "production", AppID: apnsReg.AppID, Token: apnsReg.Token}) {
		t.Fatalf("apns got %+v", g.apns.sent)
	}
	g.clk.add(3 * time.Second)
	if _, err := g.vault().Wake(ctx, sk, sb); err != nil || g.apns.sent[1].Environment != "sandbox" {
		t.Fatalf("sandbox wake: %v %+v", err, g.apns.sent)
	}
	// The raw answer: 202 and an empty object.
	g.clk.add(3 * time.Second)
	a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(fb), key: fk})
	if a.status != 202 || strings.TrimSpace(a.body) != "{}" {
		t.Fatalf("answer: %d %q", a.status, a.body)
	}
	if g.count("wakes", "platform", "fcm", "environment", "none", "outcome", "sent") != 2 ||
		g.count("wakes", "platform", "apns", "environment", "production", "outcome", "sent") != 1 ||
		g.count("wakes", "platform", "apns", "environment", "sandbox", "outcome", "sent") != 1 {
		t.Error("wakes metric")
	}
}

// §5.2 step 2: a blob that does not open, has another channel, an
// unknown key, or another signer is answered blob_invalid, identically
// in every case.
func TestWakeBlobInvalid(t *testing.T) {
	g := newGW(t)
	key, wb := g.register(fcmReg)
	_, otherBlob := g.register(apnsReg)

	prodKeys, _ := blob.NewKeyring("prod", g.secret)
	pub := key.Public().(ed25519.PublicKey)
	prodBlob, _ := prodKeys.Seal(blob.Record{Platform: "fcm", AppID: fcmReg.AppID, Token: fcmReg.Token, Key: pub})
	foreign, _ := blob.NewRandomKeyring("staging")
	foreignBlob, _ := foreign.Seal(blob.Record{Platform: "fcm", AppID: fcmReg.AppID, Token: fcmReg.Token, Key: pub})
	raw, _ := base64.RawURLEncoding.DecodeString(wb)
	raw[len(raw)-3] ^= 4
	// Records this gateway would not seal, under its own key.
	seal := func(r blob.Record) string {
		r.Key = pub
		s, err := g.cfg.Keys.Seal(r)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	cases := map[string]string{
		"another registration's blob (another signer)": otherBlob,
		"a production blob":                            prodBlob,
		"an unknown key id":                            foreignBlob,
		"altered":                                      base64.RawURLEncoding.EncodeToString(raw),
		"truncated":                                    wb[:len(wb)-8],
		"garbage":                                      "AAAA",
		"not base64url":                                "a+b/c=",
		"longer than 6,144":                            strings.Repeat("A", 6145),
		"an app no longer listed":                      seal(blob.Record{Platform: "fcm", AppID: "com.example.gone", Token: "t"}),
		"an unknown platform":                          seal(blob.Record{Platform: "webpush", AppID: fcmReg.AppID, Token: "t"}),
		"a malformed apns token":                       seal(blob.Record{Platform: "apns", Environment: "production", AppID: "com.vettid.app", Token: "../../x"}),
	}
	var first string
	for name, b := range cases {
		g.clk.add(time.Second)
		a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(b), key: key})
		if !a.is(410, "blob_invalid") {
			t.Errorf("%s: %d %s", name, a.status, a.body)
		}
		if first == "" {
			first = a.body
		} else if a.body != first {
			t.Errorf("%s: an answer that differs (an oracle): %s", name, a.body)
		}
	}
	if g.fcm.count()+g.apns.count() != 0 {
		t.Fatal("an invalid blob reached a platform")
	}
	// The vault drops the registration on blob_invalid.
	g.clk.add(time.Second)
	_, err := g.vault().Wake(context.Background(), newKey(t), wb)
	if ge := gwErr(err); ge == nil || !ge.Gone() || ge.Code != pushwire.CodeBlobInvalid {
		t.Fatalf("vault client: %v", err)
	}
}

// A sandbox blob is not sent by a production gateway even if it holds
// the key (§10.4).
func TestWakeSandboxOnProduction(t *testing.T) {
	g := newGW(t)
	sandbox := apnsReg
	sandbox.Environment = "sandbox"
	key, wb := g.register(sandbox)
	g.cfg.AllowSandbox = false
	g.rebuild()
	if a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: key}); !a.is(410, "blob_invalid") {
		t.Fatalf("%d %s", a.status, a.body)
	}
}

// §5.2: class is notify only; the body is {wake_blob, class}; the auth
// rules are the relay's.
func TestWakeRequestRules(t *testing.T) {
	g := newGW(t)
	key, wb := g.register(fcmReg)
	for name, body := range map[string]string{
		"class sync (withdrawn)": `{"wake_blob":"` + wb + `","class":"sync"}`,
		"no class":               `{"wake_blob":"` + wb + `"}`,
		"no blob":                `{"class":"notify"}`,
		"an extra member":        `{"wake_blob":"` + wb + `","class":"notify","count":3}`,
		"blob not a string":      `{"wake_blob":7,"class":"notify"}`,
		"not JSON":               `wake`,
		"empty":                  ``,
	} {
		g.clk.add(time.Second)
		if a := g.do(rawReq{path: pushwire.PathWake, body: []byte(body), key: key}); !a.is(400, "bad_request") {
			t.Errorf("%s: %d %s", name, a.status, a.body)
		}
	}
	body := pushwire.WakeBody(wb)
	if a := g.do(rawReq{path: pushwire.PathWake, body: body}); !a.is(401, "signature_invalid") {
		t.Errorf("unsigned: %d %s", a.status, a.body)
	}
	if a := g.do(rawReq{path: pushwire.PathWake, body: body, key: key, at: t0.Add(-2 * time.Minute)}); !a.is(401, "timestamp_stale") {
		t.Errorf("stale: %d %s", a.status, a.body)
	}
	var captured http.Header
	q := rawReq{path: pushwire.PathWake, body: body, key: key, mangle: func(h http.Header) {
		if captured == nil {
			captured = h.Clone()
			return
		}
		for k, v := range captured {
			h[k] = v
		}
	}}
	g.clk.add(time.Second)
	if a := g.do(q); a.status != 202 {
		t.Fatalf("wake: %d %s", a.status, a.body)
	}
	if a := g.do(q); !a.is(401, "replay_detected") {
		t.Errorf("replay: %d %s", a.status, a.body)
	}
	if g.fcm.count() != 1 {
		t.Errorf("%d sends for one accepted wake", g.fcm.count())
	}
}

// §8: at most 60 wakes an hour per token, burst 10, whatever blob or
// wake key carries the token.
func TestWakeTokenLimit(t *testing.T) {
	g := newGW(t, func(g *gw) { g.cfg.Limits.Coalesce = 0 })
	ctx := context.Background()
	k1, b1 := g.register(fcmReg)
	k2, b2 := g.register(fcmReg) // the same token, registered again
	ko, bo := g.register(apnsReg)
	for i := 0; i < 10; i++ {
		g.clk.add(time.Millisecond)
		k, b := k1, b1
		if i%2 == 1 {
			k, b = k2, b2
		}
		if _, err := g.vault().Wake(ctx, k, b); err != nil {
			t.Fatalf("wake %d of the burst: %v", i+1, err)
		}
	}
	g.clk.add(time.Millisecond)
	a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(b1), key: k1})
	if !a.is(429, "rate_limited") || a.retry != 60 || a.header.Get("Retry-After") != "60" {
		t.Fatalf("11th wake: %d %s", a.status, a.body)
	}
	if g.fcm.count() != 10 {
		t.Fatalf("%d sends", g.fcm.count())
	}
	if g.count("rate_limited", "scope", "token") != 1 || g.count("wakes", "platform", "fcm", "environment", "none", "outcome", "rate_limited") != 1 {
		t.Error("rate_limited metrics")
	}
	// The vault's client reads the wait from the body.
	g.clk.add(time.Millisecond)
	_, err := g.vault().Wake(ctx, k2, b2)
	if ge := gwErr(err); ge == nil || ge.Status != 429 || ge.Code != pushwire.CodeRateLimited || ge.RetryAfter != 60 {
		t.Fatalf("vault client: %v", err)
	}
	// Another token is unaffected.
	if _, err := g.vault().Wake(ctx, ko, bo); err != nil {
		t.Fatalf("another token: %v", err)
	}
	// One more a minute later, then limited again.
	g.clk.add(time.Minute)
	if _, err := g.vault().Wake(ctx, k1, b1); err != nil {
		t.Fatalf("after a minute: %v", err)
	}
	g.clk.add(time.Second)
	if _, err := g.vault().Wake(ctx, k1, b1); gwErr(err) == nil || gwErr(err).Status != 429 {
		t.Fatalf("second wake in that minute: %v", err)
	}
}

// §8: wakes per source address (6,000 a minute by default; 5 here).
func TestWakeAddressLimit(t *testing.T) {
	g := newGW(t, func(g *gw) { g.cfg.Limits.WakePerMinute, g.cfg.TrustProxy = 5, true })
	if DefaultLimits().WakePerMinute != 6000 || DefaultLimits().RegisterPerMinute != 30 ||
		DefaultLimits().TokenPerHour != 60 || DefaultLimits().TokenBurst != 10 || DefaultLimits().Coalesce != 2*time.Second {
		t.Fatal("default limits are not those of §8 and §5.2")
	}
	for i := 0; i < 5; i++ {
		if a := g.do(rawReq{path: pushwire.PathWake, body: []byte("{}"), xff: "203.0.113.9"}); a.status != 401 {
			t.Fatalf("request %d: %d", i+1, a.status)
		}
	}
	if a := g.do(rawReq{path: pushwire.PathWake, body: []byte("{}"), xff: "203.0.113.9"}); !a.is(429, "rate_limited") || a.retry < 1 {
		t.Fatalf("6th: %d %s", a.status, a.body)
	}
	if a := g.do(rawReq{path: pushwire.PathWake, body: []byte("{}"), xff: "203.0.113.10"}); a.status != 401 {
		t.Fatalf("another address: %d", a.status)
	}
	// Registrations have their own bucket.
	if a := g.do(rawReq{path: pushwire.PathRegister, body: []byte("{}"), xff: "203.0.113.9"}); a.status != 401 {
		t.Fatalf("register after the wake limit: %d", a.status)
	}
	if g.count("rate_limited", "scope", "address_wake") != 1 {
		t.Error("rate_limited{scope=address_wake} not counted")
	}
}

// §5.2 step 4: a wake for the same token within 2 s of the previous one
// is answered 202 without a second platform send.
func TestWakeCoalescing(t *testing.T) {
	g := newGW(t)
	ctx := context.Background()
	k1, b1 := g.register(fcmReg)
	k2, b2 := g.register(fcmReg) // the same token under another blob
	wake := func(k ed25519.PrivateKey, b string) {
		t.Helper()
		if _, err := g.vault().Wake(ctx, k, b); err != nil {
			t.Fatalf("wake: %v", err)
		}
	}
	wake(k1, b1)
	g.clk.add(1900 * time.Millisecond)
	wake(k1, b1)
	wake(k2, b2)
	if g.fcm.count() != 1 {
		t.Fatalf("%d sends within 2 s, want 1", g.fcm.count())
	}
	if g.count("wakes", "platform", "fcm", "environment", "none", "outcome", "coalesced") != 2 {
		t.Error("coalesced wakes not counted")
	}
	g.clk.add(100 * time.Millisecond) // 2 s after the send
	wake(k1, b1)
	if g.fcm.count() != 2 {
		t.Fatalf("%d sends, want a second one 2 s after the first", g.fcm.count())
	}
	// A failed send is not something to coalesce into: the next wake is
	// sent, not answered 202 for nothing.
	g.clk.add(10 * time.Second)
	g.fcm.set(provider.Result{Outcome: provider.Unavailable})
	if _, err := g.vault().Wake(ctx, k1, b1); gwErr(err) == nil || gwErr(err).Status != 502 {
		t.Fatalf("failing send: %v", err)
	}
	g.fcm.set(provider.Result{})
	g.clk.add(500 * time.Millisecond)
	wake(k1, b1)
	if g.fcm.count() != 4 {
		t.Fatalf("%d sends: the wake after a failed send was swallowed", g.fcm.count())
	}
}

// §4, §5.2: a wake whose blob was sealed under a retired key is sent and
// answered with a reseal, the same record under the current key, which
// the vault stores; once the old key is deleted its blobs are invalid.
func TestWakeReseal(t *testing.T) {
	g := newGW(t)
	ctx := context.Background()
	key, old := g.register(apnsReg)
	oldRec, _, _ := g.cfg.Keys.Open(old)
	_, oldID := g.cfg.Keys.KeyIDs()

	g.clk.add(400 * 24 * time.Hour) // a year on: the key is rotated
	rotated, err := blob.RotateSecret(g.secret)
	if err != nil {
		t.Fatal(err)
	}
	g.secret = rotated
	g.rebuild()

	reseal, err := g.vault().Wake(ctx, key, old)
	if err != nil || reseal == "" || reseal == old {
		t.Fatalf("wake under a retired key: reseal %q err %v", reseal, err)
	}
	if g.apns.count() != 1 {
		t.Fatal("the wake was not sent")
	}
	rec, current, err := g.cfg.Keys.Open(reseal)
	if err != nil || !current {
		t.Fatalf("the reseal is not under the current key: %v", err)
	}
	if rec.Platform != oldRec.Platform || rec.Environment != oldRec.Environment || rec.AppID != oldRec.AppID ||
		rec.Token != oldRec.Token || !rec.Key.Equal(oldRec.Key) || rec.Issued != oldRec.Issued {
		t.Fatalf("the reseal is not the same record: %+v vs %+v", rec, oldRec)
	}
	if g.count("blob_resealed") != 1 {
		t.Error("blob_resealed not counted")
	}
	// The new blob wakes without a reseal; the old one still works (and
	// is resealed again) until its key is deleted.
	g.clk.add(3 * time.Second)
	if r, err := g.vault().Wake(ctx, key, reseal); err != nil || r != "" {
		t.Fatalf("wake with the reseal: %q %v", r, err)
	}
	g.clk.add(time.Second) // within 2 s: coalesced, and still resealed
	if r, err := g.vault().Wake(ctx, key, old); err != nil || r == "" || g.apns.count() != 2 {
		t.Fatalf("coalesced wake under the retired key: reseal %q err %v sends %d", r, err, g.apns.count())
	}
	// A failed wake carries no reseal.
	g.clk.add(3 * time.Second)
	g.apns.set(provider.Result{Outcome: provider.Unavailable})
	if a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(old), key: key}); a.status != 502 || strings.Contains(a.body, "reseal") {
		t.Fatalf("failed wake: %d %s", a.status, a.body)
	}
	g.apns.set(provider.Result{})

	dropped, err := blob.DropKey(g.secret, oldID)
	if err != nil {
		t.Fatal(err)
	}
	g.secret = dropped
	g.rebuild()
	g.clk.add(3 * time.Second)
	if _, err := g.vault().Wake(ctx, key, old); gwErr(err) == nil || gwErr(err).Code != pushwire.CodeBlobInvalid {
		t.Fatalf("a deleted key's blob: %v", err)
	}
	if _, err := g.vault().Wake(ctx, key, reseal); err != nil {
		t.Fatalf("the resealed blob after the old key's deletion: %v", err)
	}
}

// §7: each platform outcome's answer, as the vault's client reads it.
func TestWakeFailureFeedback(t *testing.T) {
	g := newGW(t)
	ctx := context.Background()
	key, wb := g.register(fcmReg)
	cases := []struct {
		name    string
		res     provider.Result
		status  int
		code    string
		retry   int
		gone    bool
		outcome string
	}{
		{"FCM UNREGISTERED / APNs 410", provider.Result{Outcome: provider.TokenGone}, 410, "token_gone", 0, true, "token_gone"},
		{"APNs BadDeviceToken / FCM INVALID_ARGUMENT", provider.Result{Outcome: provider.TokenInvalid}, 400, "token_invalid", 0, true, "token_invalid"},
		{"the platform's 429", provider.Result{Outcome: provider.RateLimited, RetryAfter: 120}, 429, "rate_limited", 120, false, "provider_rate_limited"},
		{"the platform's 429 without a wait", provider.Result{Outcome: provider.RateLimited}, 429, "rate_limited", 0, false, "provider_rate_limited"},
		{"platform 5xx", provider.Result{Outcome: provider.Unavailable, RetryAfter: 7, Detail: "UNAVAILABLE"}, 502, "provider_unavailable", 7, false, "provider_unavailable"},
		{"timeout", provider.Result{Outcome: provider.Unavailable, Detail: "timeout"}, 502, "provider_unavailable", 0, false, "provider_unavailable"},
		{"credentials refused", provider.Result{Outcome: provider.AuthFailed, Detail: "InvalidProviderToken"}, 502, "provider_unavailable", 0, false, "provider_auth"},
		{"another refusal", provider.Result{Outcome: provider.Rejected, Detail: "BadTopic"}, 502, "provider_unavailable", 0, false, "provider_rejected"},
	}
	for _, c := range cases {
		g.clk.add(10 * time.Minute)
		g.fcm.set(c.res)
		_, err := g.vault().Wake(ctx, key, wb)
		ge := gwErr(err)
		if ge == nil || ge.Status != c.status || ge.Code != c.code || ge.RetryAfter != c.retry || ge.Gone() != c.gone {
			t.Errorf("%s: %v (%+v)", c.name, err, ge)
		}
		if g.count("wakes", "platform", "fcm", "environment", "none", "outcome", c.outcome) < 1 {
			t.Errorf("%s: wakes{outcome=%s} not counted", c.name, c.outcome)
		}
	}
	// The wait is also in the Retry-After header.
	g.clk.add(10 * time.Minute)
	g.fcm.set(provider.Result{Outcome: provider.Unavailable, RetryAfter: 33})
	if a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: key}); !a.is(502, "provider_unavailable") || a.retry != 33 || a.header.Get("Retry-After") != "33" {
		t.Errorf("502: %d %s Retry-After %q", a.status, a.body, a.header.Get("Retry-After"))
	}
	if g.count("provider_latency_ms", "platform", "fcm") != 0 {
		t.Error("provider_latency_ms is a distribution, not a counter")
	}
}

// A panic inside a handler is answered 500 internal; the log names its
// type, never its value.
func TestPanicIsInternal(t *testing.T) {
	g := newGW(t)
	key, wb := g.register(fcmReg)
	g.cfg.Providers["fcm"] = panicProvider{}
	g.rebuild()
	a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: key})
	if !a.is(500, "internal") {
		t.Fatalf("%d %s", a.status, a.body)
	}
	if g.count("internal_errors") != 1 {
		t.Error("internal_errors not counted")
	}
	if l := g.logs.String(); !strings.Contains(l, "panic in handler") || strings.Contains(l, "SECRET-IN-PANIC") {
		t.Fatalf("log: %s", l)
	}
}

type panicProvider struct{}

func (panicProvider) Send(context.Context, provider.Message) provider.Result {
	panic("SECRET-IN-PANIC")
}
