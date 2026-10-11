package attest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/manifest"
	"github.com/vettid/vettid-vault/vms/nitro"

	"github.com/vettid/vettid-push/internal/nsmtest"
)

var t0 = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

func now() time.Time { return t0 }

func reason(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	if err == nil {
		return "ok"
	}
	return "?"
}

// §5.1 step 2, every rule: the chain to the pinned root, the COSE
// signature, the 300 s window, public_key, user_data and PCR0.
func TestVerify(t *testing.T) {
	nsm := nsmtest.New(0xa0, now)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	digest := sha256.Sum256([]byte("canonical"))
	otherDigest := sha256.Sum256([]byte("another request"))
	v := &Verifier{Roots: nsm.Roots(), Releases: StaticReleases{nsm.PCR0Hex()}, Now: now}
	hdr := func(doc []byte) []string { return []string{nsmtest.Header(doc)} }
	good := nsm.AttestAt(t0, digest[:], nil, pub)

	if err := v.Verify(hdr(good), pub, digest); err != nil {
		t.Fatalf("a genuine document: %v", err)
	}

	flipped := append([]byte(nil), good...)
	flipped[len(flipped)-1] ^= 1
	payload := append([]byte(nil), good...)
	payload[strings.Index(string(payload), "module_id")+12] ^= 1
	stranger := nsmtest.New(0xa0, now) // same PCRs, another PKI

	cases := []struct {
		name   string
		header []string
		key    ed25519.PublicKey
		digest [32]byte
		want   Reason
	}{
		{"no header", nil, pub, digest, ReasonMissing},
		{"empty header", []string{""}, pub, digest, ReasonMissing},
		{"two headers", []string{nsmtest.Header(good), nsmtest.Header(good)}, pub, digest, ReasonMissing},
		{"not base64", []string{"!!!"}, pub, digest, ReasonMalformed},
		{"base64url", []string{base64.RawURLEncoding.EncodeToString(good)}, pub, digest, ReasonMalformed},
		{"not CBOR", hdr([]byte("hello")), pub, digest, ReasonMalformed},
		{"oversized", []string{strings.Repeat("A", maxHeader+4)}, pub, digest, ReasonMalformed},
		{"flipped signature", hdr(flipped), pub, digest, ReasonSignature},
		{"altered payload", hdr(payload), pub, digest, ReasonSignature},
		{"another root", hdr(stranger.AttestAt(t0, digest[:], nil, pub)), pub, digest, ReasonChain},
		{"301 s old", hdr(nsm.AttestAt(t0.Add(-301*time.Second), digest[:], nil, pub)), pub, digest, ReasonStale},
		{"301 s ahead", hdr(nsm.AttestAt(t0.Add(301*time.Second), digest[:], nil, pub)), pub, digest, ReasonStale},
		{"another key signs the request", hdr(good), other, digest, ReasonPublicKey},
		{"no public_key", hdr(nsm.AttestAt(t0, digest[:], nil, nil)), pub, digest, ReasonPublicKey},
		{"another request's digest", hdr(good), pub, otherDigest, ReasonUserData},
		{"no user_data", hdr(nsm.AttestAt(t0, nil, nil, pub)), pub, digest, ReasonUserData},
	}
	for _, c := range cases {
		if got := reason(v.Verify(c.header, c.key, c.digest)); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	// The window's edges are inside.
	for _, d := range []time.Duration{-300 * time.Second, 300 * time.Second} {
		if err := v.Verify(hdr(nsm.AttestAt(t0.Add(d), digest[:], nil, pub)), pub, digest); err != nil {
			t.Errorf("a document %v from now: %v", d, err)
		}
	}

	// PCR0: another release, and no release list at all.
	v2 := &Verifier{Roots: nsm.Roots(), Releases: StaticReleases{nsmtest.PCRHex(0x11)}, Now: now}
	if got := reason(v2.Verify(hdr(good), pub, digest)); got != ReasonPCR0 {
		t.Errorf("unlisted PCR0: %s", got)
	}
	if got := reason((&Verifier{Roots: nsm.Roots(), Releases: StaticReleases{}, Now: now}).Verify(hdr(good), pub, digest)); got != ReasonPCR0 {
		t.Errorf("empty release list: %s", got)
	}
	if got := reason((&Verifier{Roots: nsm.Roots(), Releases: &Manifests{}, Now: now}).Verify(hdr(good), pub, digest)); got != ReasonNoManifest {
		t.Errorf("no manifest loaded: %s", got)
	}
	if got := reason((&Verifier{Roots: nsm.Roots(), Now: now}).Verify(hdr(good), pub, digest)); got != ReasonNoManifest {
		t.Errorf("no releases: %s", got)
	}
	if got := reason((&Verifier{Releases: StaticReleases{nsm.PCR0Hex()}, Now: now}).Verify(hdr(good), pub, digest)); got != ReasonChain {
		t.Errorf("no roots: %s", got)
	}
	// Errors carry the reason only, never document bytes.
	if s := v.Verify(hdr(flipped), pub, digest).Error(); len(s) > 64 {
		t.Errorf("error text %q", s)
	}
	// The set of reasons is closed and complete (the metric dimension).
	seen := map[Reason]bool{}
	for _, r := range Reasons {
		seen[r] = true
	}
	for _, c := range cases {
		if !seen[c.want] {
			t.Errorf("reason %s is not listed", c.want)
		}
	}
}

// The pinned AWS Nitro Enclaves root anchors a real NSM document (chain
// and COSE signature), and nothing else: a test PKI's document is
// refused under it, and a real document is refused under a test root.
func TestPinnedNitroRoot(t *testing.T) {
	b, err := os.ReadFile("testdata/aws-attestation-2025-09-16.b64")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := nitro.Verify(raw, NitroRoots())
	if err != nil {
		t.Fatalf("the pinned root does not anchor a real document: %v", err)
	}
	at := func() time.Time { return doc.Timestamp }
	hdr := []string{base64.StdEncoding.EncodeToString(raw)}
	var digest [32]byte
	copy(digest[:], doc.UserData)
	rel := StaticReleases{doc.PCRHex(0)}

	// Its public_key is not an Ed25519 wake key: every earlier check
	// passes and the document stops exactly there.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if got := reason((&Verifier{Roots: NitroRoots(), Releases: rel, Now: at}).Verify(hdr, pub, digest)); got != ReasonPublicKey {
		t.Fatalf("real document under the pinned root: %s, want %s", got, ReasonPublicKey)
	}
	// It is long stale today.
	if got := reason((&Verifier{Roots: NitroRoots(), Releases: rel, Now: now}).Verify(hdr, pub, digest)); got != ReasonStale {
		t.Fatalf("a 2025 document today: %s", got)
	}
	nsm := nsmtest.New(1, at)
	if got := reason((&Verifier{Roots: nsm.Roots(), Releases: rel, Now: at}).Verify(hdr, pub, digest)); got != ReasonChain {
		t.Fatalf("real document under a test root: %s", got)
	}
	td := nsm.AttestAt(doc.Timestamp, digest[:], nil, pub)
	if got := reason((&Verifier{Roots: NitroRoots(), Releases: StaticReleases{nsm.PCR0Hex()}, Now: at}).Verify([]string{nsmtest.Header(td)}, pub, digest)); got != ReasonChain {
		t.Fatalf("test document under the pinned root: %s", got)
	}
	if NitroRoot().Subject.CommonName != "aws.nitro-enclaves" {
		t.Fatalf("pinned root is %q", NitroRoot().Subject.CommonName)
	}
}

// §10.4: production pins keys A and B and the production manifest;
// staging its own key and manifest; nothing else has pins.
func TestChannelPins(t *testing.T) {
	ids := func(tr Trust) (out []string) {
		for _, k := range tr.ManifestKeys {
			id, err := manifest.KeyID(k)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, id)
		}
		return
	}
	prod, err := TrustFor(ChannelProd)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(prod); len(got) != 2 || got[0] != "4353463f85c4012f" || got[1] != "1abd49da96970b6e" {
		t.Fatalf("production manifest keys %v, want A and B", got)
	}
	if prod.ManifestURL != "https://vettid.org/.well-known/vettid/pcr-manifest.json" {
		t.Fatal(prod.ManifestURL)
	}
	st, err := TrustFor(ChannelStaging)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(st); len(got) != 1 || got[0] != "e9b3a403423120ac" {
		t.Fatalf("staging manifest keys %v", got)
	}
	if st.ManifestURL != "https://staging.vettid.org/.well-known/vettid/pcr-manifest.json" {
		t.Fatal(st.ManifestURL)
	}
	for _, c := range []string{ChannelDev, "", "production"} {
		if _, err := TrustFor(c); err == nil {
			t.Errorf("channel %q has pins", c)
		}
	}
	if _, err := ParseManifestKey("AAAA"); err == nil {
		t.Fatal("a malformed manifest key parsed")
	}
}

// §5.1 step 2: the manifest is verified with the pinned keys; releases
// that are active or deprecated register, retired and removed ones do
// not; a lower serial is refused.
func TestManifests(t *testing.T) {
	signer, stranger := nsmtest.NewManifestSigner(), nsmtest.NewManifestSigner()
	rel := func(n uint64, b byte, status string) manifest.Release {
		return nsmtest.Release(n, nsmtest.PCRHex(b), status)
	}
	m := &Manifests{Keys: prodLike(signer)}
	if ok, why := m.Admits(nsmtest.PCRHex(4)); ok || why != ReasonNoManifest {
		t.Fatal("an empty holder admits or claims a manifest")
	}
	if err := m.Load(signer.Served(7, rel(1, 1, manifest.StatusRemoved), rel(2, 2, manifest.StatusRetired),
		rel(3, 3, manifest.StatusDeprecated), rel(4, 4, manifest.StatusActive))); err != nil {
		t.Fatal(err)
	}
	for b, want := range map[byte]bool{1: false, 2: false, 3: true, 4: true, 9: false} {
		if ok, why := m.Admits(nsmtest.PCRHex(b)); ok != want || why != "" {
			t.Errorf("PCR0 %02x: admitted %v, want %v", b, ok, want)
		}
	}
	if m.Serial() != 7 {
		t.Fatal(m.Serial())
	}
	// A lower serial, and the same serial with other bytes, are refused
	// and change nothing.
	if err := m.Load(signer.Served(6, rel(9, 9, manifest.StatusActive))); !errors.Is(err, ErrRollback) {
		t.Fatalf("lower serial: %v", err)
	}
	if err := m.Load(signer.Served(7, rel(9, 9, manifest.StatusActive))); !errors.Is(err, ErrRollback) {
		t.Fatalf("same serial, other bytes: %v", err)
	}
	// A manifest signed with a key the channel does not pin.
	if err := m.Load(stranger.Served(8, rel(9, 9, manifest.StatusActive))); !errors.Is(err, manifest.ErrKey) {
		t.Fatalf("unpinned key: %v", err)
	}
	// A pinned key id with a bad signature.
	bad := signer.Served(8, rel(9, 9, manifest.StatusActive))
	s, _ := manifest.ParseServed(bad)
	s.Sig[5] ^= 1
	if err := m.Load(s.Marshal()); !errors.Is(err, manifest.ErrSignature) {
		t.Fatalf("bad signature: %v", err)
	}
	if err := m.Load([]byte("{}")); err == nil {
		t.Fatal("an empty document loaded")
	}
	if ok, _ := m.Admits(nsmtest.PCRHex(9)); ok || m.Serial() != 7 {
		t.Fatal("a refused manifest changed the trusted one")
	}
	// The same manifest again is fine; a higher serial replaces it.
	if err := m.Load(signer.Served(8, rel(4, 4, manifest.StatusRetired), rel(5, 5, manifest.StatusActive))); err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.Admits(nsmtest.PCRHex(4)); ok {
		t.Fatal("a release retired by the new manifest still registers")
	}
	if ok, _ := m.Admits(nsmtest.PCRHex(5)); !ok {
		t.Fatal("the new release does not register")
	}
}

func prodLike(s *nsmtest.ManifestSigner) []*ecdsaPub { return []*ecdsaPub{&s.Key.PublicKey} }

// Fetching: 200, 404 (nothing published yet), errors, an oversized
// answer; and the periodic refresh.
func TestManifestRefresh(t *testing.T) {
	signer := nsmtest.NewManifestSigner()
	var body atomic.Value
	var status atomic.Int32
	status.Store(200)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write(body.Load().([]byte))
	}))
	defer srv.Close()
	m := &Manifests{URL: srv.URL, Keys: prodLike(signer)}
	ctx := context.Background()

	body.Store([]byte("not found"))
	status.Store(404)
	if err := m.Refresh(ctx); !errors.Is(err, ErrNotPublished) {
		t.Fatalf("404: %v", err)
	}
	status.Store(503)
	if err := m.Refresh(ctx); !errors.Is(err, ErrFetch) {
		t.Fatalf("503: %v", err)
	}
	status.Store(200)
	body.Store(make([]byte, manifest.MaxServed+10))
	if err := m.Refresh(ctx); err == nil {
		t.Fatal("an oversized document loaded")
	}
	body.Store(signer.Served(3, nsmtest.Release(1, nsmtest.PCRHex(1), manifest.StatusActive)))
	if err := m.Refresh(ctx); err != nil || m.Serial() != 3 {
		t.Fatalf("refresh: %v serial %d", err, m.Serial())
	}
	if err := (&Manifests{URL: "http://127.0.0.1:1/none", Keys: prodLike(signer)}).Refresh(ctx); !errors.Is(err, ErrFetch) {
		t.Fatalf("no server: %v", err)
	}

	// The loop picks up the next publication and reports outcomes.
	body.Store(signer.Served(4, nsmtest.Release(1, nsmtest.PCRHex(1), manifest.StatusDeprecated),
		nsmtest.Release(2, nsmtest.PCRHex(2), manifest.StatusActive)))
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	var oks atomic.Int32
	go func() {
		m.Run(rctx, 5*time.Millisecond, func(err error) {
			if err == nil {
				oks.Add(1)
			}
		})
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for m.Serial() != 4 || oks.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the refresh loop did not load serial 4")
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	<-done
	if ok, _ := m.Admits(nsmtest.PCRHex(2)); !ok {
		t.Fatal("release 2 does not register after the refresh")
	}
}

// §14.2 question 15: a manifest is trusted for 7 days since the last
// successful refresh. Just under: trusted. At and after: refused as
// manifest_stale, whatever the PCR0, until a refresh succeeds; a refresh
// that fails renews nothing. Nothing of it outlives the holder.
func TestManifestMaxAge(t *testing.T) {
	signer := nsmtest.NewManifestSigner()
	var body atomic.Value
	var status atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write(body.Load().([]byte))
	}))
	defer srv.Close()
	at := t0
	clock := func() time.Time { return at }
	m := &Manifests{URL: srv.URL, Keys: prodLike(signer), Now: clock}
	ctx := context.Background()
	listed, unlisted := nsmtest.PCRHex(1), nsmtest.PCRHex(9)
	check := func(when string, wantOK bool, wantWhy Reason) {
		t.Helper()
		if ok, why := m.Admits(listed); ok != wantOK || why != wantWhy {
			t.Fatalf("%s: admitted %v (%q), want %v (%q)", when, ok, why, wantOK, wantWhy)
		}
		if ok, why := m.Admits(unlisted); ok || why != wantWhy {
			t.Fatalf("%s, unlisted PCR0: admitted %v (%q)", when, ok, why)
		}
		if m.Stale() != (wantWhy == ReasonManifestStale) {
			t.Fatalf("%s: Stale() = %v", when, m.Stale())
		}
	}
	serve := func(code int, b []byte) { status.Store(int32(code)); body.Store(b) }
	v5 := signer.Served(5, nsmtest.Release(1, listed, manifest.StatusActive))

	// No manifest is not a stale one, however long it lasts: a channel
	// that has published nothing, and a site that cannot be reached.
	serve(404, []byte("not found"))
	if err := m.Refresh(ctx); !errors.Is(err, ErrNotPublished) {
		t.Fatal(err)
	}
	at = at.Add(30 * 24 * time.Hour)
	check("nothing published for a month", false, ReasonNoManifest)

	serve(200, v5)
	if err := m.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	good := at
	check("just refreshed", true, "")

	// Every kind of failed refresh, for a week: none renews the manifest.
	failures := []struct {
		code int
		body []byte
		want error
	}{
		{503, []byte("down"), ErrFetch},
		{404, []byte("not found"), ErrNotPublished}, // unpublished after it was published
		{200, signer.Served(4, nsmtest.Release(1, listed, manifest.StatusActive)), ErrRollback},
		{200, nsmtest.NewManifestSigner().Served(6, nsmtest.Release(1, listed, manifest.StatusActive)), manifest.ErrKey},
	}
	for i, f := range failures {
		at = good.Add(time.Duration(i+1) * 24 * time.Hour)
		serve(f.code, f.body)
		if err := m.Refresh(ctx); !errors.Is(err, f.want) {
			t.Fatalf("failure %d: %v", i, err)
		}
		check("a failed refresh within the week", true, "")
	}
	at = good.Add(MaxManifestAge - time.Nanosecond)
	check("just under 7 days", true, "")
	at = good.Add(MaxManifestAge)
	check("at 7 days", false, ReasonManifestStale)
	at = good.Add(MaxManifestAge + 90*24*time.Hour)
	check("long after", false, ReasonManifestStale)
	if m.Serial() != 5 {
		t.Fatalf("a stale manifest lost its serial: %d", m.Serial())
	}
	// Still failing: still stale, and the serial rule still holds.
	if err := m.Refresh(ctx); !errors.Is(err, manifest.ErrKey) {
		t.Fatal(err)
	}
	serve(200, signer.Served(4, nsmtest.Release(9, unlisted, manifest.StatusActive)))
	if err := m.Refresh(ctx); !errors.Is(err, ErrRollback) {
		t.Fatalf("a lower serial while stale: %v", err)
	}
	check("after failed refreshes while stale", false, ReasonManifestStale)

	// The same manifest served again is a successful refresh: trust is
	// back at once, for another 7 days from now.
	serve(200, v5)
	if err := m.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	check("refreshed after being stale", true, "")
	good = at
	at = good.Add(MaxManifestAge - time.Second)
	check("just under 7 days after the second refresh", true, "")
	// A new manifest renews it as well.
	serve(200, signer.Served(6, nsmtest.Release(1, listed, manifest.StatusDeprecated)))
	if err := m.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	at = at.Add(MaxManifestAge - time.Second)
	check("just under 7 days after serial 6", true, "")
	at = at.Add(time.Second)
	check("7 days after serial 6", false, ReasonManifestStale)

	// A restart: nothing is persisted. The new holder has no manifest
	// (not a stale one) while the site is away, then trusts what the site
	// serves, a lower serial included, for a full 7 days from then.
	m = &Manifests{URL: srv.URL, Keys: prodLike(signer), Now: clock}
	serve(503, []byte("down"))
	if err := m.Refresh(ctx); !errors.Is(err, ErrFetch) {
		t.Fatal(err)
	}
	check("restarted without the site", false, ReasonNoManifest)
	serve(200, v5)
	if err := m.Refresh(ctx); err != nil || m.Serial() != 5 {
		t.Fatalf("restart: %v serial %d", err, m.Serial())
	}
	at = at.Add(MaxManifestAge - time.Nanosecond)
	check("restarted, just under 7 days", true, "")
	at = at.Add(time.Nanosecond)
	check("restarted, at 7 days", false, ReasonManifestStale)

	// The verifier reports it as its own reason, after the document's
	// own checks.
	nsm := nsmtest.New(1, clock)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	digest := sha256.Sum256([]byte("canonical"))
	v := &Verifier{Roots: nsm.Roots(), Releases: m, Now: clock}
	doc := []string{nsmtest.Header(nsm.AttestAt(at, digest[:], nil, pub))}
	if got := reason(v.Verify(doc, pub, digest)); got != ReasonManifestStale {
		t.Fatalf("a registration under a stale manifest: %s", got)
	}
	if got := reason(v.Verify(doc, pub, sha256.Sum256([]byte("another")))); got != ReasonUserData {
		t.Fatalf("the document's own checks come first: %s", got)
	}
	if MaxManifestAge != 7*24*time.Hour {
		t.Fatal(MaxManifestAge)
	}
	// The default clock is the system's.
	d := &Manifests{Keys: prodLike(signer)}
	if err := d.Load(v5); err != nil {
		t.Fatal(err)
	}
	if ok, why := d.Admits(listed); !ok || why != "" || d.Stale() {
		t.Fatalf("default clock: %v %q", ok, why)
	}
}
