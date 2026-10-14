package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-vault/vms/pushwire"

	"github.com/vettid/vettid-push/internal/attest"
	"github.com/vettid/vettid-push/internal/blob"
	"github.com/vettid/vettid-push/internal/metrics"
	"github.com/vettid/vettid-push/internal/nsmtest"
	"github.com/vettid/vettid-push/internal/provider"
)

var t0 = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

type clock struct {
	mu sync.Mutex
	t  time.Time
	// step, if set, passes between one reading and the next.
	step time.Duration
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.t
	c.t = c.t.Add(c.step)
	return t
}
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }
func (c *clock) set(t time.Time, step time.Duration) {
	c.mu.Lock()
	c.t, c.step = t, step
	c.mu.Unlock()
}

// fakeProvider records what the gateway hands a platform client: wakes
// in sent, registration challenges in chals (the phone that holds the
// token would receive those).
type fakeProvider struct {
	mu         sync.Mutex
	sent       []provider.Message
	result     provider.Result
	chals      []provider.Message
	chalResult provider.Result
}

func (f *fakeProvider) Send(_ context.Context, m provider.Message) provider.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m.Challenge != "" {
		f.chals = append(f.chals, m)
		return f.chalResult
	}
	f.sent = append(f.sent, m)
	return f.result
}
func (f *fakeProvider) set(r provider.Result)     { f.mu.Lock(); f.result = r; f.mu.Unlock() }
func (f *fakeProvider) setChal(r provider.Result) { f.mu.Lock(); f.chalResult = r; f.mu.Unlock() }
func (f *fakeProvider) count() int                { f.mu.Lock(); defer f.mu.Unlock(); return len(f.sent) }
func (f *fakeProvider) chalCount() int            { f.mu.Lock(); defer f.mu.Unlock(); return len(f.chals) }

// lastChallenge is the most recent challenge sent to token.
func (f *fakeProvider) lastChallenge(token string) (provider.Message, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.chals) - 1; i >= 0; i-- {
		if f.chals[i].Token == token {
			return f.chals[i], true
		}
	}
	return provider.Message{}, false
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// gw is a gateway under test with a fake NSM, a fake clock and fake
// platform clients.
type gw struct {
	t       *testing.T
	clk     *clock
	nsm     *nsmtest.NSM
	cfg     Config
	srv     *Server
	http    *httptest.Server
	fcm     *fakeProvider
	apns    *fakeProvider
	logs    *syncBuffer
	metrics *metrics.Registry
	secret  []byte
}

type opt func(*gw)

func newGW(t *testing.T, opts ...opt) *gw { t.Helper(); return newGWAt(t, t0, opts...) }

// newGWAt is newGW with the clock (and the fake NSM's certificates) at
// another time.
func newGWAt(t *testing.T, at time.Time, opts ...opt) *gw {
	t.Helper()
	g := &gw{t: t, clk: &clock{t: at}, fcm: &fakeProvider{}, apns: &fakeProvider{}, logs: &syncBuffer{}}
	g.nsm = nsmtest.New(0xa0, g.clk.now)
	sec, err := blob.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	g.secret = sec
	g.metrics = metrics.New("test", g.clk.now)
	g.cfg = Config{
		Channel:      "staging",
		Providers:    map[string]provider.Provider{provider.FCM: g.fcm, provider.APNs: g.apns},
		AppIDs:       map[string][]string{provider.FCM: {"com.vettid.app.staging"}, provider.APNs: {"com.vettid.app.staging", "com.vettid.app"}},
		AllowSandbox: true,
		Limits:       DefaultLimits(),
		Metrics:      g.metrics,
		Log:          slog.New(slog.NewJSONHandler(g.logs, nil)),
		Now:          g.clk.now,
	}
	// Tests register the same few tokens many times; the challenge
	// limit has its own test, with the default.
	g.cfg.Limits.ChallengeBurst = 1000
	for _, o := range opts {
		o(g)
	}
	g.rebuild()
	return g
}

// rebuild (re)creates the server from g.cfg and g.secret, as a restart
// with a changed secret would.
func (g *gw) rebuild() {
	g.t.Helper()
	keys, err := blob.NewKeyring(g.cfg.Channel, g.secret)
	if err != nil {
		g.t.Fatal(err)
	}
	g.cfg.Keys = keys
	if g.cfg.Attest == nil {
		g.cfg.Attest = &attest.Verifier{Roots: g.nsm.Roots(), Releases: attest.StaticReleases{g.nsm.PCR0Hex()}, Now: g.clk.now}
	}
	srv, err := New(g.cfg)
	if err != nil {
		g.t.Fatal(err)
	}
	g.srv = srv
	if g.http != nil {
		g.http.Close()
	}
	g.http = httptest.NewServer(srv)
	g.t.Cleanup(g.http.Close)
}

// vault returns the vault's own gateway client (vettid-vault
// vms/pushwire), attesting with the fake NSM as the enclave's supervisor
// does.
func (g *gw) vault() *pushwire.Client {
	return &pushwire.Client{BaseURL: g.http.URL, HTTP: g.http.Client(), Now: g.clk.now, Attest: g.nsm.Attester()}
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var (
	fcmReg  = pushwire.Registration{Platform: "fcm", Token: "dQw4:APA91bH_fcm-token", AppID: "com.vettid.app.staging"}
	apnsReg = pushwire.Registration{Platform: "apns", Token: "740f4707bebcf74f9b7c25d48e3358945f6aa01da5ddb387462c7eaf61bb78ad",
		AppID: "com.vettid.app.staging", Environment: "production"}
)

// register registers r with a fresh wake key, both steps: the
// registration, then the confirmation with the code the phone received.
func (g *gw) register(r pushwire.Registration) (ed25519.PrivateKey, string) {
	g.t.Helper()
	k := newKey(g.t)
	return k, g.registerWith(k, r)
}

// registerWith is register with a given wake key.
func (g *gw) registerWith(k ed25519.PrivateKey, r pushwire.Registration) string {
	g.t.Helper()
	pending := g.registerPending(k, r)
	a := g.confirm(k, pending, g.code(r))
	if a.status != http.StatusCreated {
		g.t.Fatalf("confirm: %d %s", a.status, a.body)
	}
	wb, err := pushwire.ParseRegistered([]byte(a.body))
	if err != nil {
		g.t.Fatalf("confirm answer %s: %v", a.body, err)
	}
	return wb
}

// registerPending sends the registration (first step) and returns the
// pending registration of its 202.
func (g *gw) registerPending(k ed25519.PrivateKey, r pushwire.Registration) string {
	g.t.Helper()
	a := g.do(rawReq{path: pushwire.PathRegister, body: r.Body(), key: k})
	p, ok := parsePending(a)
	if !ok {
		g.t.Fatalf("register: %d %s", a.status, a.body)
	}
	return p
}

// parsePending reads a registration's 202 {pending}.
func parsePending(a answer) (string, bool) {
	var v struct {
		Pending string `json:"pending"`
	}
	if a.status != http.StatusAccepted || json.Unmarshal([]byte(a.body), &v) != nil || !pushwire.ValidBlob(v.Pending) {
		return "", false
	}
	return v.Pending, true
}

// code is the challenge code the phone holding r's token last received.
func (g *gw) code(r pushwire.Registration) string {
	g.t.Helper()
	if d := g.cfg.Dev; d != nil {
		th := sha256.Sum256([]byte(r.Token))
		cs := d.Challenges()
		for i := len(cs) - 1; i >= 0; i-- {
			if cs[i].TokenSHA256 == hex.EncodeToString(th[:]) {
				return cs[i].Code
			}
		}
		g.t.Fatal("the stand-in recorded no challenge for the token")
	}
	p := g.fcm
	if r.Platform == provider.APNs {
		p = g.apns
	}
	m, ok := p.lastChallenge(r.Token)
	if !ok {
		g.t.Fatal("no challenge was sent to the token")
	}
	return m.Challenge
}

// confirmBody is the body of POST /v1/confirm.
func confirmBody(pending, code string) []byte {
	b, _ := json.Marshal(struct {
		Pending string `json:"pending"`
		Code    string `json:"code"`
	}{pending, code})
	return b
}

// confirm sends the second step, signed by k.
func (g *gw) confirm(k ed25519.PrivateKey, pending, code string) answer {
	g.t.Helper()
	return g.do(rawReq{path: PathConfirm, body: confirmBody(pending, code), key: k})
}

// answer is a raw gateway answer.
type answer struct {
	status int
	header http.Header
	body   string
	code   string
	retry  int
}

type rawReq struct {
	path    string
	body    []byte
	key     ed25519.PrivateKey
	at      time.Time // signature time (default: now)
	attest  *string   // nil: a genuine attestation for register, none for wake
	xff     string
	mangle  func(http.Header)
	method  string
	rawPath string
}

// do sends a signed request built by hand, for the cases the vault
// client never produces.
func (g *gw) do(q rawReq) answer {
	g.t.Helper()
	if q.method == "" {
		q.method = http.MethodPost
	}
	if q.at.IsZero() {
		q.at = g.clk.now()
	}
	target := q.path
	if q.rawPath != "" {
		target = q.rawPath
	}
	req, err := http.NewRequest(q.method, g.http.URL+target, bytes.NewReader(q.body))
	if err != nil {
		g.t.Fatal(err)
	}
	if q.key != nil {
		bh := relayauth.BodyHash(q.body)
		relayauth.SetHeaders(req.Header, q.key, http.MethodPost, q.path, q.at, bh)
		switch {
		case q.attest != nil:
			if *q.attest != "" {
				req.Header.Set(pushwire.HeaderAttestation, *q.attest)
			}
		case q.path == pushwire.PathRegister:
			d := relayauth.Digest(http.MethodPost, q.path, req.Header.Get(relayauth.HeaderTimestamp), bh)
			doc, _ := g.nsm.Attest(d[:], nil, q.key.Public().(ed25519.PublicKey))
			req.Header.Set(pushwire.HeaderAttestation, nsmtest.Header(doc))
		}
	}
	if q.xff != "" {
		req.Header.Set("X-Forwarded-For", q.xff)
	}
	if q.mangle != nil {
		q.mangle(req.Header)
	}
	resp, err := g.http.Client().Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	a := answer{status: resp.StatusCode, header: resp.Header, body: string(b)}
	var e struct {
		Code       string `json:"code"`
		RetryAfter int    `json:"retry_after"`
	}
	if json.Unmarshal(b, &e) == nil {
		a.code, a.retry = e.Code, e.RetryAfter
	}
	return a
}

func (a answer) is(status int, code string) bool { return a.status == status && a.code == code }

func (g *gw) count(name string, dims ...string) float64 {
	var d []metrics.Dim
	for i := 0; i+1 < len(dims); i += 2 {
		d = append(d, metrics.Dim{Name: dims[i], Value: dims[i+1]})
	}
	return g.metrics.Value(name, d...)
}

func str(s string) *string { return &s }

func logLines(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
