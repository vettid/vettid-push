package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// apnsSecretFor returns an APNs secret around a fresh P-256 key in
// Apple's .p8 form (generated here; no real key is a fixture).
func apnsSecretFor(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	b, _ := json.Marshal(map[string]string{"team_id": "TEAM123456", "key_id": "KEY1234567",
		"p8": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	return b, key
}

type apnsReq struct {
	proto  int
	method string
	path   string
	header http.Header
	body   string
}

type apnsFake struct {
	mu      sync.Mutex
	reqs    []apnsReq
	respond func(n int, w http.ResponseWriter, r *http.Request)
}

func (f *apnsFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.reqs = append(f.reqs, apnsReq{r.ProtoMajor, r.Method, r.URL.Path, r.Header.Clone(), string(b)})
	n := len(f.reqs)
	f.mu.Unlock()
	if f.respond != nil {
		f.respond(n, w, r)
	}
}

// h2Server is a local HTTP/2 TLS server, as APNs is.
func h2Server(h http.Handler) *httptest.Server {
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	return srv
}

func apnsClient(t *testing.T, secret []byte, prod, sandbox *httptest.Server, now func() time.Time) *APNsClient {
	t.Helper()
	c, err := NewAPNsClient(secret)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	for _, s := range []*httptest.Server{prod, sandbox} {
		if s != nil {
			pool.AddCert(s.Certificate())
		}
	}
	c.HTTP = NewAPNsHTTPClient(pool)
	c.Now = now
	if prod != nil {
		c.ProductionURL = prod.URL
	}
	if sandbox != nil {
		c.SandboxURL = sandbox.URL
	}
	return c
}

const apnsToken = "740f4707bebcf74f9b7c25d48e3358945f6aa01da5ddb387462c7eaf61bb78ad"

// §6: the APNs request over HTTP/2 with token-based auth: the fixed
// headers and payload, no collapse id, no thread id, no interruption
// level; the host follows the blob's environment.
func TestAPNsRequest(t *testing.T) {
	secret, key := apnsSecretFor(t)
	prodFake, sandFake := &apnsFake{}, &apnsFake{}
	prod, sand := h2Server(prodFake), h2Server(sandFake)
	defer prod.Close()
	defer sand.Close()
	c := apnsClient(t, secret, prod, sand, func() time.Time { return t0 })
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if r := c.Send(ctx, Message{Platform: APNs, Environment: EnvProduction, AppID: "com.vettid.app", Token: apnsToken}); r.Outcome != Sent {
			t.Fatalf("production send: %+v", r)
		}
	}
	if r := c.Send(ctx, Message{Platform: APNs, Environment: EnvSandbox, AppID: "com.vettid.app.staging", Token: apnsToken}); r.Outcome != Sent {
		t.Fatalf("sandbox send: %+v", r)
	}
	if len(prodFake.reqs) != 2 || len(sandFake.reqs) != 1 {
		t.Fatalf("%d production and %d sandbox requests", len(prodFake.reqs), len(sandFake.reqs))
	}
	r := prodFake.reqs[0]
	if r.proto != 2 {
		t.Fatalf("HTTP/%d, APNs requires HTTP/2", r.proto)
	}
	if r.method != "POST" || r.path != "/3/device/"+apnsToken {
		t.Fatalf("%s %s", r.method, r.path)
	}
	const want = `{"aps":{"alert":{"loc-key":"WAKE_FALLBACK"},"mutable-content":1,"sound":"default"}}`
	if r.body != want {
		t.Fatalf("payload\n got %s\nwant %s", r.body, want)
	}
	if prodFake.reqs[1].body != r.body || sandFake.reqs[0].body != r.body {
		t.Fatal("payloads differ between wakes")
	}
	for k, v := range map[string]string{"apns-push-type": "alert", "apns-priority": "10", "apns-topic": "com.vettid.app",
		"apns-expiration": strconv.FormatInt(t0.Unix()+86400, 10)} {
		if r.header.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, r.header.Get(k), v)
		}
	}
	for _, k := range []string{"apns-collapse-id", "apns-id"} {
		if r.header.Get(k) != "" {
			t.Errorf("%s is set", k)
		}
	}
	for _, banned := range []string{"thread-id", "interruption-level", "content-available", "badge", "body", "title"} {
		if strings.Contains(r.body, banned) {
			t.Errorf("payload has %q", banned)
		}
	}
	if sandFake.reqs[0].header.Get("apns-topic") != "com.vettid.app.staging" {
		t.Error("sandbox topic")
	}
	// The provider token: ES256 over the team id and the issue time,
	// with the key id; reused between sends.
	auth := r.header.Get("authorization")
	if !strings.HasPrefix(auth, "bearer ") {
		t.Fatalf("authorization %q", auth[:10])
	}
	parts := strings.Split(strings.TrimPrefix(auth, "bearer "), ".")
	if len(parts) != 3 {
		t.Fatal("not a JWT")
	}
	var head map[string]string
	var claims map[string]any
	_ = json.Unmarshal(b64dec(t, parts[0]), &head)
	_ = json.Unmarshal(b64dec(t, parts[1]), &claims)
	if head["alg"] != "ES256" || head["kid"] != "KEY1234567" || len(head) != 2 {
		t.Fatalf("JWT header %v", head)
	}
	if claims["iss"] != "TEAM123456" || int64(claims["iat"].(float64)) != t0.Unix() || len(claims) != 2 {
		t.Fatalf("JWT claims %v", claims)
	}
	sig := b64dec(t, parts[2])
	d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(&key.PublicKey, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("JWT signature does not verify under the .p8 key")
	}
	if prodFake.reqs[1].header.Get("authorization") != auth || sandFake.reqs[0].header.Get("authorization") != auth {
		t.Fatal("the provider token was not reused")
	}
	if DefaultAPNsProductionURL != "https://api.push.apple.com" || DefaultAPNsSandboxURL != "https://api.sandbox.push.apple.com" {
		t.Fatal("APNs hosts changed")
	}
	if r := c.Send(ctx, Message{Platform: APNs, Environment: "", AppID: "a", Token: apnsToken}); r.Outcome != Rejected {
		t.Fatalf("no environment: %+v", r)
	}
}

func apnsErr(status int, reason string) func(int, http.ResponseWriter, *http.Request) {
	return func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		fmt.Fprintf(w, `{"reason":%q,"timestamp":1760000000000}`, reason)
	}
}

// §7: APNs' answers.
func TestAPNsOutcomes(t *testing.T) {
	secret, _ := apnsSecretFor(t)
	cases := []struct {
		name    string
		respond func(int, http.ResponseWriter, *http.Request)
		want    Outcome
		detail  string
		retry   int
	}{
		{"Unregistered", apnsErr(410, "Unregistered"), TokenGone, "Unregistered", 0},
		{"ExpiredToken", apnsErr(410, "ExpiredToken"), TokenGone, "ExpiredToken", 0},
		{"BadDeviceToken", apnsErr(400, "BadDeviceToken"), TokenInvalid, "BadDeviceToken", 0},
		{"DeviceTokenNotForTopic", apnsErr(400, "DeviceTokenNotForTopic"), TokenInvalid, "DeviceTokenNotForTopic", 0},
		{"InvalidProviderToken", apnsErr(403, "InvalidProviderToken"), AuthFailed, "InvalidProviderToken", 0},
		{"BadCertificateEnvironment", apnsErr(403, "BadCertificateEnvironment"), AuthFailed, "BadCertificateEnvironment", 0},
		{"TooManyRequests", func(_ int, w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "30")
			apnsErr(429, "TooManyRequests")(0, w, r)
		}, RateLimited, "TooManyRequests", 30},
		{"TooManyProviderTokenUpdates", apnsErr(429, "TooManyProviderTokenUpdates"), RateLimited, "TooManyProviderTokenUpdates", 0},
		{"InternalServerError", apnsErr(500, "InternalServerError"), Unavailable, "InternalServerError", 0},
		{"Shutdown", func(_ int, w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "5")
			apnsErr(503, "Shutdown")(0, w, r)
		}, Unavailable, "Shutdown", 5},
		{"BadTopic", apnsErr(400, "BadTopic"), Rejected, "BadTopic", 0},
		{"TopicDisallowed", apnsErr(400, "TopicDisallowed"), Rejected, "TopicDisallowed", 0},
		{"PayloadTooLarge", apnsErr(413, "PayloadTooLarge"), Rejected, "PayloadTooLarge", 0},
		{"unknown reason", apnsErr(400, "Something "+apnsToken), Rejected, "other", 0},
	}
	for _, c := range cases {
		fake := &apnsFake{respond: c.respond}
		srv := h2Server(fake)
		cl := apnsClient(t, secret, srv, nil, func() time.Time { return t0 })
		r := cl.Send(context.Background(), Message{Platform: APNs, Environment: EnvProduction, AppID: "com.vettid.app", Token: apnsToken})
		srv.Close()
		if r.Outcome != c.want || r.Detail != c.detail || r.RetryAfter != c.retry {
			t.Errorf("%s: %+v, want %v %q retry %d", c.name, r, c.want, c.detail, c.retry)
		}
	}
}

// Apple refuses a provider token older than an hour and one refreshed
// more often than every 20 minutes: the token is reused for 45 minutes,
// and ExpiredProviderToken renews it only once it is 20 minutes old.
func TestAPNsProviderTokenLifetime(t *testing.T) {
	secret, _ := apnsSecretFor(t)
	clk := newClock()
	var mu sync.Mutex
	expired := map[string]bool{}
	fake := &apnsFake{respond: func(_ int, w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		bad := expired[r.Header.Get("authorization")]
		mu.Unlock()
		if bad {
			apnsErr(403, "ExpiredProviderToken")(0, w, r)
		}
	}}
	srv := h2Server(fake)
	defer srv.Close()
	c := apnsClient(t, secret, srv, nil, clk.now)
	msg := Message{Platform: APNs, Environment: EnvProduction, AppID: "com.vettid.app", Token: apnsToken}
	send := func() (Result, string) {
		r := c.Send(context.Background(), msg)
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return r, fake.reqs[len(fake.reqs)-1].header.Get("authorization")
	}
	_, first := send()
	clk.add(44 * time.Minute)
	if _, tok := send(); tok != first {
		t.Fatal("the provider token changed within 45 minutes")
	}
	clk.add(2 * time.Minute)
	_, second := send()
	if second == first {
		t.Fatal("the provider token was not renewed after 45 minutes")
	}
	// Apple calls the fresh token expired after 5 minutes: too young to
	// renew, so the retry carries the same token and the send fails as an
	// auth failure.
	clk.add(5 * time.Minute)
	mu.Lock()
	expired[second] = true
	mu.Unlock()
	n := len(fake.reqs)
	r, tok := send()
	if r.Outcome != AuthFailed || r.Detail != "ExpiredProviderToken" || tok != second || len(fake.reqs) != n+2 {
		t.Fatalf("young token: %+v, %d requests", r, len(fake.reqs)-n)
	}
	// At 20 minutes it is renewed and the send retried once.
	clk.add(15 * time.Minute)
	n = len(fake.reqs)
	r, tok = send()
	if r.Outcome != Sent || tok == second || len(fake.reqs) != n+2 {
		t.Fatalf("renewal on ExpiredProviderToken: %+v, %d requests", r, len(fake.reqs)-n)
	}
}

func TestAPNsTimeout(t *testing.T) {
	secret, _ := apnsSecretFor(t)
	release := make(chan struct{})
	srv := h2Server(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	c := apnsClient(t, secret, srv, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if r := c.Send(ctx, Message{Platform: APNs, Environment: EnvProduction, AppID: "a", Token: apnsToken}); r.Outcome != Unavailable || r.Detail != "timeout" {
		t.Fatalf("%+v", r)
	}
}

func TestAPNsSecretValidation(t *testing.T) {
	good, _ := apnsSecretFor(t)
	edit := func(f func(map[string]string)) []byte {
		var m map[string]string
		_ = json.Unmarshal(good, &m)
		f(m)
		b, _ := json.Marshal(m)
		return b
	}
	rsaLike, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(rsaLike)
	bad := map[string][]byte{
		"not JSON":     []byte("x"),
		"empty":        []byte("{}"),
		"short team":   edit(func(m map[string]string) { m["team_id"] = "TEAM" }),
		"lowercase id": edit(func(m map[string]string) { m["key_id"] = "key1234567" }),
		"no p8":        edit(func(m map[string]string) { m["p8"] = "" }),
		"garbage p8":   edit(func(m map[string]string) { m["p8"] = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n" }),
		"P-384 key": edit(func(m map[string]string) {
			m["p8"] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		}),
	}
	for name, s := range bad {
		if _, err := NewAPNsClient(s); !errors.Is(err, ErrAPNsSecret) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := NewAPNsClient(good); err != nil {
		t.Fatal(err)
	}
}
