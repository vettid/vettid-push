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
	if ok, loaded := m.Admits(nsmtest.PCRHex(4)); ok || loaded {
		t.Fatal("an empty holder admits or claims a manifest")
	}
	if err := m.Load(signer.Served(7, rel(1, 1, manifest.StatusRemoved), rel(2, 2, manifest.StatusRetired),
		rel(3, 3, manifest.StatusDeprecated), rel(4, 4, manifest.StatusActive))); err != nil {
		t.Fatal(err)
	}
	for b, want := range map[byte]bool{1: false, 2: false, 3: true, 4: true, 9: false} {
		if ok, loaded := m.Admits(nsmtest.PCRHex(b)); ok != want || !loaded {
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
