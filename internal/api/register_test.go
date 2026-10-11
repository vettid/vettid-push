package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-vault/vms/manifest"
	"github.com/vettid/vettid-vault/vms/pushwire"

	"github.com/vettid/vettid-push/internal/attest"
	"github.com/vettid/vettid-push/internal/nsmtest"
)

// §5.1 with the vault's own client: a registration is answered 201 with
// a blob that holds the record and the wake key; no platform is
// contacted; the same body twice yields two blobs that both work.
func TestRegister(t *testing.T) {
	g := newGW(t)
	for _, reg := range []pushwire.Registration{fcmReg, apnsReg,
		{Platform: "apns", Token: apnsReg.Token, AppID: "com.vettid.app", Environment: "sandbox"}} {
		key, wb := g.register(reg)
		if !pushwire.ValidBlob(wb) {
			t.Fatalf("the vault would refuse this blob: %q", wb)
		}
		rec, current, err := g.cfg.Keys.Open(wb)
		if err != nil || !current {
			t.Fatal(err)
		}
		if rec.Platform != reg.Platform || rec.Environment != reg.Environment || rec.AppID != reg.AppID || rec.Token != reg.Token ||
			!bytes.Equal(rec.Key, key.Public().(ed25519.PublicKey)) || rec.Issued != t0.Unix() {
			t.Fatalf("record %+v", rec)
		}
	}
	if g.fcm.count()+g.apns.count() != 0 {
		t.Fatal("registering contacted a platform")
	}
	key := newKey(t)
	g.clk.add(time.Second)
	a, err := g.vault().Register(context.Background(), key, fcmReg)
	if err != nil {
		t.Fatal(err)
	}
	g.clk.add(time.Second)
	b, err := g.vault().Register(context.Background(), key, fcmReg)
	if err != nil || a == b {
		t.Fatalf("the same body twice: err %v, identical %v", err, a == b)
	}
	for _, wb := range []string{a, b} {
		g.clk.add(3 * time.Second)
		if _, err := g.vault().Wake(context.Background(), key, wb); err != nil {
			t.Fatalf("wake with one of two blobs: %v", err)
		}
	}
	if g.count("registrations", "platform", "fcm", "outcome", "ok") != 3 || g.count("registrations", "platform", "apns", "outcome", "ok") != 2 {
		t.Fatal("registrations metric")
	}
}

// §5.1 step 1 (Relay Protocol §4.1): signature, 90 s freshness, replay.
func TestRegisterAuth(t *testing.T) {
	g := newGW(t)
	key := newKey(t)
	body := fcmReg.Body()
	cases := []struct {
		name string
		q    rawReq
		code string
	}{
		{"unsigned", rawReq{path: pushwire.PathRegister, body: body}, "signature_invalid"},
		{"signed for another body", rawReq{path: pushwire.PathRegister, body: body, key: key, mangle: func(h http.Header) {
			tmp := http.Header{}
			relayauth.SetHeaders(tmp, key, "POST", pushwire.PathRegister, g.clk.now(), relayauth.BodyHash([]byte("{}")))
			h.Set(relayauth.HeaderSig, tmp.Get(relayauth.HeaderSig))
		}}, "signature_invalid"},
		{"signed for another path", rawReq{path: pushwire.PathRegister, body: body, key: key, mangle: func(h http.Header) {
			tmp := http.Header{}
			relayauth.SetHeaders(tmp, key, "POST", pushwire.PathWake, g.clk.now(), relayauth.BodyHash(body))
			h.Set(relayauth.HeaderSig, tmp.Get(relayauth.HeaderSig))
			h.Set(relayauth.HeaderTimestamp, tmp.Get(relayauth.HeaderTimestamp))
		}}, "signature_invalid"},
		{"malformed key", rawReq{path: pushwire.PathRegister, body: body, key: key, mangle: func(h http.Header) { h.Set(relayauth.HeaderKey, "AAAA") }}, "signature_invalid"},
		{"91 s old", rawReq{path: pushwire.PathRegister, body: body, key: key, at: t0.Add(-91 * time.Second)}, "timestamp_stale"},
		{"91 s ahead", rawReq{path: pushwire.PathRegister, body: body, key: key, at: t0.Add(91 * time.Second)}, "timestamp_stale"},
	}
	for _, c := range cases {
		if a := g.do(c.q); !a.is(401, c.code) {
			t.Errorf("%s: %d %s", c.name, a.status, a.body)
		}
	}
	// 89 s either way is fresh (the attestation is made now).
	for _, d := range []time.Duration{-89 * time.Second, 89 * time.Second} {
		if a := g.do(rawReq{path: pushwire.PathRegister, body: body, key: newKey(t), at: t0.Add(d)}); a.status != 201 {
			t.Errorf("%v: %d %s", d, a.status, a.body)
		}
	}
	// Replay: the identical signed request a second time.
	var captured http.Header
	q := rawReq{path: pushwire.PathRegister, body: body, key: key, mangle: func(h http.Header) {
		if captured == nil {
			captured = h.Clone()
			return
		}
		for k, v := range captured {
			h[k] = v
		}
	}}
	if a := g.do(q); a.status != 201 {
		t.Fatalf("first: %d %s", a.status, a.body)
	}
	if a := g.do(q); !a.is(401, "replay_detected") {
		t.Fatalf("replay: %d %s", a.status, a.body)
	}
	// An oversized body is refused before anything is verified.
	if a := g.do(rawReq{path: pushwire.PathRegister, body: bytes.Repeat([]byte("x"), MaxBody+1), key: key}); !a.is(400, "bad_request") {
		t.Fatalf("oversized: %d %s", a.status, a.body)
	}
	// The vault maps a 401 at registration to gateway_error, no retry:
	// its client sees the code.
	c := g.vault()
	c.Now = func() time.Time { return t0.Add(-time.Hour) }
	_, err := c.Register(context.Background(), newKey(t), fcmReg)
	var ge *pushwire.Error
	if !errors.As(err, &ge) || ge.Status != 401 || ge.Code != pushwire.CodeTimestampStale {
		t.Fatalf("vault client: %v", err)
	}
}

// §5.1 step 2: only an attested vault release of the channel registers.
func TestRegisterAttestation(t *testing.T) {
	g := newGW(t)
	body := fcmReg.Body()
	key := newKey(t)
	pub := key.Public().(ed25519.PublicKey)
	stranger := nsmtest.New(0xa0, g.clk.now)
	otherRelease := *g.nsm
	otherRelease.PCRs = map[uint64][]byte{0: nsmtest.PCR(0x77), 1: nsmtest.PCR(1), 2: nsmtest.PCR(2)}
	debug := *g.nsm
	debug.PCRs = map[uint64][]byte{0: nsmtest.PCR(0), 1: nsmtest.PCR(0), 2: nsmtest.PCR(0)}
	otherKey := newKey(t).Public().(ed25519.PublicKey)

	// build makes the attestation header for the request about to be
	// sent, from the digest the gateway will compute.
	type build func(digest [32]byte) string
	cases := []struct {
		name   string
		b      build
		reason string
	}{
		{"no attestation", func([32]byte) string { return "" }, "missing"},
		{"garbage", func([32]byte) string { return "bm90IGEgZG9jdW1lbnQ=" }, "malformed"},
		{"another PKI", func(d [32]byte) string { return nsmtest.Header(stranger.AttestAt(g.clk.now(), d[:], nil, pub)) }, "chain"},
		{"stale", func(d [32]byte) string {
			return nsmtest.Header(g.nsm.AttestAt(g.clk.now().Add(-6*time.Minute), d[:], nil, pub))
		}, "stale"},
		{"another wake key", func(d [32]byte) string { return nsmtest.Header(g.nsm.AttestAt(g.clk.now(), d[:], nil, otherKey)) }, "public_key"},
		{"another request", func(d [32]byte) string { d[0] ^= 1; return nsmtest.Header(g.nsm.AttestAt(g.clk.now(), d[:], nil, pub)) }, "user_data"},
		{"unlisted release", func(d [32]byte) string { return nsmtest.Header(otherRelease.AttestAt(g.clk.now(), d[:], nil, pub)) }, "pcr0"},
		{"debug enclave", func(d [32]byte) string { return nsmtest.Header(debug.AttestAt(g.clk.now(), d[:], nil, pub)) }, "pcr0"},
	}
	var first string
	for i, c := range cases {
		g.clk.add(time.Second) // a distinct timestamp, so no replay
		at := g.clk.now()
		d := relayauth.Digest("POST", pushwire.PathRegister, at.UTC().Format(time.RFC3339Nano), relayauth.BodyHash(body))
		a := g.do(rawReq{path: pushwire.PathRegister, body: body, key: key, at: at, attest: str(c.b(d))})
		if !a.is(403, "attestation_invalid") {
			t.Errorf("%s: %d %s", c.name, a.status, a.body)
		}
		// One answer for every reason.
		if i == 0 {
			first = a.body
		} else if a.body != first {
			t.Errorf("%s: the answer differs from the others: %s", c.name, a.body)
		}
		if g.count("attestation_failures", "reason", c.reason) < 1 {
			t.Errorf("%s: attestation_failures{reason=%s} not counted", c.name, c.reason)
		}
	}
	// Two attestation headers are refused.
	g.clk.add(time.Second)
	if a := g.do(rawReq{path: pushwire.PathRegister, body: body, key: key, mangle: func(h http.Header) {
		h.Add(pushwire.HeaderAttestation, h.Get(pushwire.HeaderAttestation))
	}}); !a.is(403, "attestation_invalid") {
		t.Errorf("two headers: %d %s", a.status, a.body)
	}
	// Order: the signature is checked before the attestation, the
	// attestation before the body.
	g.clk.add(time.Second)
	if a := g.do(rawReq{path: pushwire.PathRegister, body: body, key: key, at: t0.Add(-time.Hour), attest: str("")}); !a.is(401, "timestamp_stale") {
		t.Errorf("stale and unattested: %d %s", a.status, a.body)
	}
	if a := g.do(rawReq{path: pushwire.PathRegister, body: []byte(`{"platform":"nope"}`), key: key, attest: str("")}); !a.is(403, "attestation_invalid") {
		t.Errorf("unattested bad body: %d %s", a.status, a.body)
	}
	if g.count("registrations", "platform", "unknown", "outcome", "attestation_invalid") < 9 {
		t.Error("registrations{outcome=attestation_invalid} not counted")
	}
}

// §5.1 step 2: PCR0 against the channel's signed manifest. Active and
// deprecated releases register; retired, removed and unlisted ones do
// not; without a manifest nobody does; a new manifest takes effect at
// once.
func TestRegisterManifest(t *testing.T) {
	signer := nsmtest.NewManifestSigner()
	m := &attest.Manifests{Keys: signer.Keys()}
	g := newGW(t, func(g *gw) {
		g.cfg.Attest = &attest.Verifier{Roots: g.nsm.Roots(), Releases: m, Now: g.clk.now}
	})
	// The manifest's age has a clock of its own here: the test enclave's
	// certificates do not live a week.
	age := &clock{t: g.clk.now()}
	m.Now = age.now
	try := func() answer {
		g.clk.add(time.Second)
		return g.do(rawReq{path: pushwire.PathRegister, body: fcmReg.Body(), key: newKey(t)})
	}
	if a := try(); !a.is(403, "attestation_invalid") || g.count("attestation_failures", "reason", "no_manifest") != 1 {
		t.Fatalf("no manifest: %d %s", a.status, a.body)
	}
	pcr0 := g.nsm.PCR0Hex()
	for i, c := range []struct {
		status string
		want   int
	}{{manifest.StatusActive, 201}, {manifest.StatusDeprecated, 201}, {manifest.StatusRetired, 403}, {manifest.StatusRemoved, 403}} {
		rel := []manifest.Release{nsmtest.Release(1, pcr0, c.status), nsmtest.Release(2, nsmtest.PCRHex(0x55), manifest.StatusActive)}
		if err := m.Load(signer.Served(uint64(10+i), rel...)); err != nil {
			t.Fatal(err)
		}
		if a := try(); a.status != c.want {
			t.Errorf("release %s: %d %s", c.status, a.status, a.body)
		}
	}
	if err := m.Load(signer.Served(20, nsmtest.Release(2, nsmtest.PCRHex(0x55), manifest.StatusActive))); err != nil {
		t.Fatal(err)
	}
	dropped := try()
	if !dropped.is(403, "attestation_invalid") {
		t.Errorf("a release dropped from the manifest: %d %s", dropped.status, dropped.body)
	}

	// §14.2 question 15: 7 days after the last successful refresh the
	// manifest is no longer trusted. The answer is the one of every other
	// attestation refusal; only the metric names the reason. A wake with
	// a blob sealed before is not affected: it consults no manifest.
	vault := newKey(t)
	if err := m.Load(signer.Served(21, nsmtest.Release(1, pcr0, manifest.StatusActive))); err != nil {
		t.Fatal(err)
	}
	g.clk.add(time.Second)
	reg := g.do(rawReq{path: pushwire.PathRegister, body: fcmReg.Body(), key: vault})
	if reg.status != 201 {
		t.Fatalf("register: %d %s", reg.status, reg.body)
	}
	wb, _ := pushwire.ParseRegistered([]byte(reg.body))
	age.add(attest.MaxManifestAge - time.Hour)
	if a := try(); a.status != 201 {
		t.Errorf("under 7 days: %d %s", a.status, a.body)
	}
	if g.count("attestation_failures", "reason", "manifest_stale") != 0 {
		t.Error("manifest_stale counted before the limit")
	}
	age.add(time.Hour)
	a := try()
	if !a.is(403, "attestation_invalid") || a.body != dropped.body {
		t.Errorf("stale manifest: %d %s (other refusals: %s)", a.status, a.body, dropped.body)
	}
	if g.count("attestation_failures", "reason", "manifest_stale") != 1 {
		t.Error("attestation_failures{reason=manifest_stale} not counted")
	}
	g.clk.add(time.Second)
	if a := g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: vault}); a.status != 202 || g.fcm.count() != 1 {
		t.Errorf("a wake under a stale manifest: %d %s", a.status, a.body)
	}
	// A successful refresh, of the same manifest, restores trust.
	if err := m.Load(signer.Served(21, nsmtest.Release(1, pcr0, manifest.StatusActive))); err != nil {
		t.Fatal(err)
	}
	if a := try(); a.status != 201 {
		t.Errorf("after a refresh: %d %s", a.status, a.body)
	}
}

// §5.1 step 3 and §7: the body's rules and the code of each refusal.
func TestRegisterBody(t *testing.T) {
	g := newGW(t)
	hex64 := strings.Repeat("ab", 32)
	cases := []struct {
		name string
		body string
		code string // "" = 201
	}{
		{"fcm", `{"platform":"fcm","token":"t","app_id":"com.vettid.app.staging"}`, ""},
		{"fcm 4096-byte token", `{"platform":"fcm","token":"` + strings.Repeat("T", 4096) + `","app_id":"com.vettid.app.staging"}`, ""},
		{"apns production", `{"platform":"apns","token":"` + hex64 + `","environment":"production","app_id":"com.vettid.app.staging"}`, ""},
		{"apns sandbox on staging", `{"platform":"apns","token":"` + hex64 + `","environment":"sandbox","app_id":"com.vettid.app.staging"}`, ""},
		{"apns 200 hex digits", `{"platform":"apns","token":"` + strings.Repeat("0f", 100) + `","environment":"production","app_id":"com.vettid.app"}`, ""},

		{"not JSON", `platform=fcm`, "bad_request"},
		{"an array", `[]`, "bad_request"},
		{"no platform", `{"token":"t","app_id":"com.vettid.app.staging"}`, "bad_request"},
		{"platform not a string", `{"platform":1,"token":"t","app_id":"com.vettid.app.staging"}`, "bad_request"},
		{"unknown member", `{"platform":"fcm","token":"t","app_id":"com.vettid.app.staging","class":"notify"}`, "bad_request"},
		{"duplicate member", `{"platform":"fcm","token":"t","token":"t","app_id":"com.vettid.app.staging"}`, "bad_request"},
		{"no token", `{"platform":"fcm","app_id":"com.vettid.app.staging"}`, "bad_request"},
		{"no app_id", `{"platform":"fcm","token":"t"}`, "bad_request"},
		{"fcm with environment", `{"platform":"fcm","token":"t","environment":"production","app_id":"com.vettid.app.staging"}`, "bad_request"},
		{"apns without environment", `{"platform":"apns","token":"` + hex64 + `","app_id":"com.vettid.app.staging"}`, "bad_request"},
		{"apns unknown environment", `{"platform":"apns","token":"` + hex64 + `","environment":"development","app_id":"com.vettid.app.staging"}`, "bad_request"},
		{"apns empty environment", `{"platform":"apns","token":"` + hex64 + `","environment":"","app_id":"com.vettid.app.staging"}`, "bad_request"},

		{"unifiedpush", `{"platform":"unifiedpush","token":"https://up.example/x","app_id":"com.vettid.app.staging"}`, "platform_invalid"},
		{"webpush", `{"platform":"webpush","token":"t","app_id":"com.vettid.app.staging"}`, "platform_invalid"},
		{"empty platform", `{"platform":"","token":"t","app_id":"com.vettid.app.staging"}`, "platform_invalid"},

		{"fcm empty token", `{"platform":"fcm","token":"","app_id":"com.vettid.app.staging"}`, "token_invalid"},
		{"fcm 4097-byte token", `{"platform":"fcm","token":"` + strings.Repeat("T", 4097) + `","app_id":"com.vettid.app.staging"}`, "token_invalid"},
		{"fcm token with a space", `{"platform":"fcm","token":"a b","app_id":"com.vettid.app.staging"}`, "token_invalid"},
		{"fcm token not ASCII", `{"platform":"fcm","token":"tök","app_id":"com.vettid.app.staging"}`, "token_invalid"},
		{"fcm token with a control", `{"platform":"fcm","token":"a\u0007b","app_id":"com.vettid.app.staging"}`, "token_invalid"},
		{"fcm token that outgrows the blob", `{"platform":"fcm","token":"` + strings.Repeat(`\"`, 4096) + `","app_id":"com.vettid.app.staging"}`, "token_invalid"},
		{"apns uppercase hex", `{"platform":"apns","token":"` + strings.ToUpper(hex64) + `","environment":"production","app_id":"com.vettid.app.staging"}`, "token_invalid"},
		{"apns 62 digits", `{"platform":"apns","token":"` + hex64[:62] + `","environment":"production","app_id":"com.vettid.app.staging"}`, "token_invalid"},
		{"apns 65 digits", `{"platform":"apns","token":"` + hex64 + `a","environment":"production","app_id":"com.vettid.app.staging"}`, "token_invalid"},
		{"apns 202 digits", `{"platform":"apns","token":"` + strings.Repeat("0f", 101) + `","environment":"production","app_id":"com.vettid.app.staging"}`, "token_invalid"},
		{"apns not hex", `{"platform":"apns","token":"` + strings.Repeat("zz", 32) + `","environment":"production","app_id":"com.vettid.app.staging"}`, "token_invalid"},

		{"app not in the list", `{"platform":"fcm","token":"t","app_id":"com.example.other"}`, "app_invalid"},
		{"an apns-only app for fcm", `{"platform":"fcm","token":"t","app_id":"com.vettid.app"}`, "app_invalid"},
		{"malformed app id", `{"platform":"fcm","token":"t","app_id":"com/vettid"}`, "app_invalid"},
		{"empty app id", `{"platform":"fcm","token":"t","app_id":""}`, "app_invalid"},
	}
	for _, c := range cases {
		g.clk.add(time.Second)
		a := g.do(rawReq{path: pushwire.PathRegister, body: []byte(c.body), key: newKey(t), xff: "198.51.100.7"})
		switch {
		case c.code == "" && a.status != 201:
			t.Errorf("%s: %d %s", c.name, a.status, a.body)
		case c.code != "" && !a.is(400, c.code):
			t.Errorf("%s: %d %s, want 400 %s", c.name, a.status, a.body, c.code)
		}
		g.clk.add(3 * time.Second) // stay under 30 registrations a minute
	}
	// Error bodies are fixed strings: they never repeat the request.
	a := g.do(rawReq{path: pushwire.PathRegister, body: []byte(`{"platform":"fcm","token":"t","app_id":"com.example.SECRETAPP"}`), key: newKey(t)})
	if strings.Contains(a.body, "SECRETAPP") || a.header.Get("Content-Type") != "application/json" {
		t.Errorf("error body %s", a.body)
	}
	// The vault's client reads each code (VAULT-MESSAGING §14.1: these
	// three become bad_request with the code as message).
	g.clk.add(time.Minute)
	_, err := g.vault().Register(context.Background(), newKey(t), pushwire.Registration{Platform: "fcm", Token: "t", AppID: "com.example.other"})
	var ge *pushwire.Error
	if !errors.As(err, &ge) || ge.Status != 400 || ge.Code != pushwire.CodeAppInvalid {
		t.Fatalf("vault client: %v", err)
	}
}

// §10.4: production accepts only the APNs production environment; a
// platform the channel has no credentials for is unknown there.
func TestRegisterChannelRules(t *testing.T) {
	g := newGW(t, func(g *gw) {
		g.cfg.Channel, g.cfg.AllowSandbox = "prod", false
		delete(g.cfg.Providers, "fcm")
	})
	sandbox := apnsReg
	sandbox.Environment = "sandbox"
	if a := g.do(rawReq{path: pushwire.PathRegister, body: sandbox.Body(), key: newKey(t)}); !a.is(400, "bad_request") {
		t.Errorf("sandbox on production: %d %s", a.status, a.body)
	}
	if a := g.do(rawReq{path: pushwire.PathRegister, body: apnsReg.Body(), key: newKey(t)}); a.status != 201 {
		t.Errorf("production on production: %d %s", a.status, a.body)
	}
	if a := g.do(rawReq{path: pushwire.PathRegister, body: fcmReg.Body(), key: newKey(t)}); !a.is(400, "platform_invalid") {
		t.Errorf("a platform without a provider: %d %s", a.status, a.body)
	}
}

// §8: at most 30 registrations a minute per source address; the source
// is the hop the load balancer appended, never a client-supplied one.
func TestRegisterAddressLimit(t *testing.T) {
	g := newGW(t, func(g *gw) { g.cfg.TrustProxy = true })
	body := []byte(`{}`) // refused later, but each request counts
	send := func(xff string) answer {
		return g.do(rawReq{path: pushwire.PathRegister, body: body, xff: xff})
	}
	for i := 0; i < 30; i++ {
		if a := send("203.0.113.9"); a.status != 401 {
			t.Fatalf("request %d: %d %s", i+1, a.status, a.body)
		}
	}
	a := send("203.0.113.9")
	if !a.is(429, "rate_limited") || a.retry != 2 || a.header.Get("Retry-After") != "2" {
		t.Fatalf("31st in a minute: %d %s (Retry-After %q)", a.status, a.body, a.header.Get("Retry-After"))
	}
	if g.count("rate_limited", "scope", "address_register") != 1 {
		t.Error("rate_limited{scope=address_register} not counted")
	}
	// A spoofed earlier hop does not buy a new bucket; another real
	// source has its own.
	if a := send("10.9.9.9, 203.0.113.9"); a.status != 429 {
		t.Errorf("spoofed first hop: %d", a.status)
	}
	if a := g.do(rawReq{path: pushwire.PathRegister, body: body, mangle: func(h http.Header) {
		h["X-Forwarded-For"] = []string{"10.8.8.8", "203.0.113.9"} // two header lines
	}}); a.status != 429 {
		t.Errorf("spoofed first header line: %d", a.status)
	}
	if a := send("203.0.113.10"); a.status != 401 {
		t.Errorf("another address: %d", a.status)
	}
	// IPv6: one /64 is one source.
	for i := 0; i < 30; i++ {
		send("2001:db8:1:2::1")
	}
	if a := send("2001:db8:1:2:ffff::9"); a.status != 429 {
		t.Errorf("same /64: %d", a.status)
	}
	if a := send("2001:db8:1:3::1"); a.status != 401 {
		t.Errorf("another /64: %d", a.status)
	}
	// Half a bucket refills in a minute.
	g.clk.add(time.Minute)
	if a := send("203.0.113.9"); a.status != 401 {
		t.Errorf("after a minute: %d", a.status)
	}
	// Without a trusted proxy the header is ignored: everything comes
	// from the peer.
	g2 := newGW(t)
	for i := 0; i < 30; i++ {
		g2.do(rawReq{path: pushwire.PathRegister, body: body, xff: "203.0.113." + string(rune('0'+i%10))})
	}
	if a := g2.do(rawReq{path: pushwire.PathRegister, body: body, xff: "198.51.100.200"}); a.status != 429 {
		t.Errorf("untrusted X-Forwarded-For moved the limit: %d", a.status)
	}
}

// §5: health is unauthenticated and answers 200 {}; nothing else exists.
func TestHealthAndUnknownRoutes(t *testing.T) {
	g := newGW(t)
	if a := g.do(rawReq{path: "/v1/health", method: "GET"}); a.status != 200 || strings.TrimSpace(a.body) != "{}" {
		t.Fatalf("health: %d %q", a.status, a.body)
	}
	for _, q := range []rawReq{
		{path: "/v1/register", method: "GET"}, {path: "/v1/wake", method: "PUT"}, {path: "/v1/health", method: "POST"},
		{path: "/v1/register/", method: "POST"}, {path: "/v1/update", method: "POST"}, {path: "/v1/wake", method: "DELETE"},
		{path: "/", method: "GET"}, {path: "/metrics", method: "GET"}, {path: "/dev/push", method: "GET"},
	} {
		if a := g.do(q); !a.is(404, "not_found") {
			t.Errorf("%s %s: %d %s", q.method, q.path, a.status, a.body)
		}
	}
}
