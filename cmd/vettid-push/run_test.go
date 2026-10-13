package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/manifest"
	"github.com/vettid/vettid-vault/vms/pushwire"

	"github.com/vettid/vettid-push/internal/attest"
	"github.com/vettid/vettid-push/internal/blob"
	"github.com/vettid/vettid-push/internal/config"
	"github.com/vettid/vettid-push/internal/nsmtest"
	"github.com/vettid/vettid-push/internal/provider"
	"github.com/vettid/vettid-push/internal/secrets"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

// recorded is one request a fake platform received.
type recorded struct {
	proto  int
	path   string
	header http.Header
	body   string
}

type fakePlatform struct {
	mu      sync.Mutex
	reqs    []recorded
	respond func(w http.ResponseWriter, r *http.Request)
}

func (f *fakePlatform) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.reqs = append(f.reqs, recorded{r.ProtoMajor, r.URL.Path, r.Header.Clone(), string(b)})
	respond := f.respond
	f.mu.Unlock()
	if respond != nil {
		respond(w, r)
		return
	}
	if strings.Contains(r.URL.Path, "messages:send") {
		_, _ = w.Write([]byte(`{"name":"projects/vettid-staging/messages/1"}`))
	}
}
func (f *fakePlatform) all() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.reqs...)
}
func (f *fakePlatform) set(h func(http.ResponseWriter, *http.Request)) {
	f.mu.Lock()
	f.respond = h
	f.mu.Unlock()
}

// xff adds the load balancer's X-Forwarded-For hop to every request.
type xff struct {
	addr string
	next http.RoundTripper
}

func (x xff) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Forwarded-For", x.addr)
	return x.next.RoundTrip(r)
}

// started runs the gateway in the background and returns its addresses
// and a stop function that returns run's error.
func started(t *testing.T, cfg config.Config, d deps) (pub, ctl string, stop func() error) {
	t.Helper()
	ready := make(chan [2]string, 1)
	d.ready = ready
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, d) }()
	select {
	case a := <-ready:
		pub, ctl = a[0], a[1]
	case err := <-done:
		cancel()
		t.Fatalf("the gateway did not start: %v", err)
	case <-time.After(20 * time.Second):
		cancel()
		t.Fatal("the gateway did not start in time")
	}
	stopped := false
	stop = func() error {
		if stopped {
			return nil
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(20 * time.Second):
			return errors.New("the gateway did not stop")
		}
	}
	t.Cleanup(func() { _ = stop() })
	return pub, ctl, stop
}

// TestStagingEndToEnd is the interoperability test: the vault's own
// gateway client (vettid-vault vms/pushwire, the code staging release 9
// ships) drives a whole gateway process, configured as a staging task,
// whose FCM and APNs clients are the real ones pointed at local fakes of
// Google's token endpoint, the FCM API and APNs. Nothing real is
// contacted, and every key and credential is generated here.
func TestStagingEndToEnd(t *testing.T) {
	const lbHop = "203.0.113.50"
	nsm := nsmtest.New(0xa0, nil)

	// The staging site with its signed manifest.
	signer := nsmtest.NewManifestSigner()
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(signer.Served(11, nsmtest.Release(8, nsmtest.PCRHex(0x08), manifest.StatusDeprecated),
			nsmtest.Release(9, nsm.PCR0Hex(), manifest.StatusActive)))
	}))
	defer site.Close()

	// Google: the OAuth token endpoint and the FCM API.
	google := &fakePlatform{}
	google.set(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_, _ = w.Write([]byte(`{"access_token":"ya29.e2e-access-token","expires_in":3600,"token_type":"Bearer"}`))
			return
		}
		_, _ = w.Write([]byte(`{"name":"projects/vettid-staging/messages/1"}`))
	})
	gsrv := httptest.NewServer(google)
	defer gsrv.Close()

	// Apple: production and sandbox, HTTP/2 over TLS.
	h2 := func(h http.Handler) *httptest.Server {
		s := httptest.NewUnstartedServer(h)
		s.EnableHTTP2 = true
		s.StartTLS()
		return s
	}
	apnsProd, apnsSand := &fakePlatform{}, &fakePlatform{}
	psrv, ssrv := h2(apnsProd), h2(apnsSand)
	defer psrv.Close()
	defer ssrv.Close()

	// The three secrets.
	blobKeys, err := blob.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	p8Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p8DER, _ := x509.MarshalPKCS8PrivateKey(p8Key)
	p8 := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8DER}))
	apnsSecret, _ := json.Marshal(map[string]string{"team_id": "TEAM123456", "key_id": "KEY1234567", "p8": p8})
	saKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	saDER, _ := x509.MarshalPKCS8PrivateKey(saKey)
	saPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: saDER}))
	fcmSecret, _ := json.Marshal(map[string]string{"type": "service_account", "project_id": "vettid-staging",
		"private_key_id": "k1", "private_key": saPEM, "client_email": "vettid-push@vettid-staging.iam.gserviceaccount.com",
		"token_uri": "https://oauth2.googleapis.com/token"})

	cfg, err := config.Load(env(map[string]string{
		"PUSH_CHANNEL": "staging", "PUSH_LISTEN_ADDR": "127.0.0.1:0", "PUSH_TRUST_PROXY": "true", "AWS_REGION": "us-east-1",
		"PUSH_FCM_APP_IDS": "com.vettid.app.staging", "PUSH_APNS_APP_IDS": "com.vettid.app.staging",
		"PUSH_METRICS_INTERVAL": "1h",
	}), false)
	if err != nil {
		t.Fatal(err)
	}
	out := &syncBuf{}
	pool := x509.NewCertPool()
	pool.AddCert(psrv.Certificate())
	pool.AddCert(ssrv.Certificate())
	d := deps{
		out:     out,
		lookup:  env(nil),
		secrets: secrets.Map{secrets.BlobKeys: blobKeys, secrets.APNs: apnsSecret, secrets.FCM: fcmSecret},
		trust:   &attest.Trust{ManifestURL: site.URL, ManifestKeys: signer.Keys()},
		roots:   nsm.Roots(),
		providers: func(platform string, secret []byte) (provider.Provider, string, error) {
			switch platform {
			case provider.APNs:
				c, err := provider.NewAPNsClient(secret)
				if err != nil {
					return nil, "", err
				}
				c.ProductionURL, c.SandboxURL, c.HTTP = psrv.URL, ssrv.URL, provider.NewAPNsHTTPClient(pool)
				return c, "p8_key", nil
			default:
				ts, kind, project, err := provider.NewFCMTokenSource(secret, provider.FCMAuthOptions{OAuthTokenURL: gsrv.URL + "/token"})
				if err != nil {
					return nil, "", err
				}
				return &provider.FCMClient{Project: project, Tokens: ts, BaseURL: gsrv.URL}, string(kind), nil
			}
		},
	}
	pub, _, stop := started(t, cfg, d)

	// The vault: its client, attesting through the (fake) NSM as the
	// enclave's supervisor does, behind the load balancer's hop.
	vault := &pushwire.Client{BaseURL: "http://" + pub, Attest: nsm.Attester(),
		HTTP: &http.Client{Transport: xff{lbHop, http.DefaultTransport}, Timeout: 10 * time.Second}}
	ctx := context.Background()
	newKey := func() ed25519.PrivateKey { _, k, _ := ed25519.GenerateKey(rand.Reader); return k }

	// Health, as the target group asks.
	resp, err := http.Get("http://" + pub + "/v1/health")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("health: %v", err)
	}
	hb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.TrimSpace(string(hb)) != "{}" {
		t.Fatalf("health body %q", hb)
	}

	// Android: register, wake.
	const fcmToken = "eXaMpLe-fcm:APA91bE2E_registration-token"
	fcmKey := newKey()
	fcmBlob, err := vault.Register(ctx, fcmKey, pushwire.Registration{Platform: "fcm", Token: fcmToken, AppID: "com.vettid.app.staging"})
	if err != nil {
		t.Fatalf("fcm register: %v", err)
	}
	if len(google.all()) != 0 {
		t.Fatal("registering contacted Google")
	}
	if reseal, err := vault.Wake(ctx, fcmKey, fcmBlob); err != nil || reseal != "" {
		t.Fatalf("fcm wake: %q %v", reseal, err)
	}
	greqs := google.all()
	if len(greqs) != 2 || greqs[0].path != "/token" || greqs[1].path != "/v1/projects/vettid-staging/messages:send" {
		t.Fatalf("Google saw %d requests: %+v", len(greqs), greqs)
	}
	if greqs[1].header.Get("Authorization") != "Bearer ya29.e2e-access-token" ||
		greqs[1].body != `{"message":{"token":"`+fcmToken+`","data":{"w":"1"},"android":{"priority":"HIGH","collapse_key":"w","ttl":"86400s"}}}` {
		t.Fatalf("FCM request: %s", greqs[1].body)
	}

	// iOS: a development build (sandbox) and a TestFlight build
	// (production) both register against staging (§10.4).
	const apnsToken = "740f4707bebcf74f9b7c25d48e3358945f6aa01da5ddb387462c7eaf61bb78ad"
	for _, c := range []struct {
		env  string
		fake *fakePlatform
	}{{"sandbox", apnsSand}, {"production", apnsProd}} {
		k := newKey()
		b, err := vault.Register(ctx, k, pushwire.Registration{Platform: "apns", Token: apnsToken, AppID: "com.vettid.app.staging", Environment: c.env})
		if err != nil {
			t.Fatalf("apns %s register: %v", c.env, err)
		}
		if _, err := vault.Wake(ctx, k, b); err != nil {
			t.Fatalf("apns %s wake: %v", c.env, err)
		}
		reqs := c.fake.all()
		if len(reqs) != 1 {
			t.Fatalf("apns %s: %d requests", c.env, len(reqs))
		}
		r := reqs[0]
		if r.proto != 2 || r.path != "/3/device/"+apnsToken || r.header.Get("apns-topic") != "com.vettid.app.staging" ||
			r.header.Get("apns-push-type") != "alert" || r.header.Get("apns-priority") != "10" ||
			r.body != `{"aps":{"alert":{"loc-key":"WAKE_FALLBACK"},"mutable-content":1,"sound":"default"}}` {
			t.Fatalf("apns %s request: HTTP/%d %s %v %s", c.env, r.proto, r.path, r.header, r.body)
		}
	}

	// A dead token: Google says UNREGISTERED, the vault drops the
	// registration.
	google.set(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"error":{"code":404,"status":"NOT_FOUND","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}`))
	})
	time.Sleep(2100 * time.Millisecond) // past the coalescing window
	_, err = vault.Wake(ctx, fcmKey, fcmBlob)
	var ge *pushwire.Error
	if !errors.As(err, &ge) || ge.Status != 410 || ge.Code != pushwire.CodeTokenGone || !ge.Gone() {
		t.Fatalf("dead token: %v", err)
	}
	// A platform outage: 502 with the platform's wait.
	google.set(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "17")
		w.WriteHeader(503)
	})
	_, err = vault.Wake(ctx, fcmKey, fcmBlob)
	if !errors.As(err, &ge) || ge.Status != 502 || ge.Code != pushwire.CodeProviderUnavailable || ge.RetryAfter != 17 {
		t.Fatalf("outage: %v", err)
	}

	// A vault of a release the manifest does not list is refused; so is
	// a wake signed by another key.
	rogue := nsmtest.New(0x66, nil)
	rogueVault := &pushwire.Client{BaseURL: "http://" + pub, Attest: rogue.Attester()}
	if _, err := rogueVault.Register(ctx, newKey(), pushwire.Registration{Platform: "fcm", Token: fcmToken, AppID: "com.vettid.app.staging"}); !errors.As(err, &ge) || ge.Status != 403 || ge.Code != pushwire.CodeAttestationInvalid {
		t.Fatalf("unlisted release: %v", err)
	}
	if _, err := vault.Wake(ctx, newKey(), fcmBlob); !errors.As(err, &ge) || ge.Code != pushwire.CodeBlobInvalid {
		t.Fatalf("another signer: %v", err)
	}

	// Noise on the listener: net/http would log the peer's address.
	if c, err := net.Dial("tcp", pub); err == nil {
		_, _ = c.Write([]byte("\x16\x03\x01 not http\r\n\r\n"))
		_, _ = io.Copy(io.Discard, c)
		c.Close()
	}

	// Graceful shutdown: run returns, the last metrics are flushed.
	if err := stop(); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if _, err := http.Get("http://" + pub + "/v1/health"); err == nil {
		t.Fatal("the listener is still open after shutdown")
	}

	// Everything the process wrote: a start line, the outage, the stop,
	// the metrics; no request data.
	all := out.String()
	var msgs []string
	metricLines := 0
	for _, l := range strings.Split(strings.TrimSpace(all), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("output line is not JSON: %q", l)
		}
		if _, ok := m["_aws"]; ok {
			metricLines++
			continue
		}
		msgs = append(msgs, fmt.Sprint(m["msg"]))
	}
	if got := strings.Join(msgs, " | "); got != "push gateway started | platform send failed | shutdown signal received; draining | push gateway stopped" {
		t.Fatalf("log lines: %s", got)
	}
	if metricLines == 0 {
		t.Fatal("no metrics were flushed at shutdown")
	}
	for name, s := range map[string]string{
		"the FCM token": fcmToken, "the APNs token": apnsToken, "a wake blob": fcmBlob, "a wake blob's start": fcmBlob[:24],
		"the wake key":            base64.StdEncoding.EncodeToString(fcmKey.Public().(ed25519.PublicKey)),
		"the source address":      lbHop,
		"the access token":        "ya29.e2e-access-token",
		"the APNs key":            p8[40:80],
		"the service account key": saPEM[40:80],
		"a blob key":              string(blobKeys[30:60]),
		"net/http's own log":      "http: ",
	} {
		if strings.Contains(all, s) {
			t.Errorf("the output contains %s", name)
		}
	}
	for _, want := range []string{`"manifest_serial":11`, `"channel":"staging"`, `"fcm_access":"service_account_key"`, `"apns_access":"p8_key"`, `"blob_keys":1`} {
		if !strings.Contains(all, want) {
			t.Errorf("the start line lacks %s", want)
		}
	}
}

// §10.4: `vettid-push -dev` accepts the dev enclave's test attestation
// and records wakes instead of sending them.
func TestDevStandIn(t *testing.T) {
	nsm := nsmtest.New(0x30, nil)
	cfg, err := config.Load(env(map[string]string{
		"PUSH_LISTEN_ADDR":    "127.0.0.1:0",
		"PUSH_DEV_NITRO_ROOT": base64.StdEncoding.EncodeToString(nsm.Root.Raw), "PUSH_DEV_PCR0S": nsm.PCR0Hex(),
	}), true)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DevControlAddr = "127.0.0.1:0" // any free port, as the listener's
	out := &syncBuf{}
	pub, ctl, stop := started(t, cfg, deps{out: out, lookup: env(nil)})
	vault := &pushwire.Client{BaseURL: "http://" + pub, Attest: nsm.Attester()}
	ctx := context.Background()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	wb, err := vault.Register(ctx, key, pushwire.Registration{Platform: "fcm", Token: "dev-token", AppID: "com.vettid.app.dev"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := vault.Wake(ctx, key, wb); err != nil {
		t.Fatalf("wake: %v", err)
	}
	resp, err := http.Get("http://" + ctl + "/dev/push")
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		Registrations int              `json:"registrations"`
		Wakes         []map[string]any `json:"wakes"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&state)
	resp.Body.Close()
	if state.Registrations != 1 || len(state.Wakes) != 1 || state.Wakes[0]["platform"] != "fcm" || state.Wakes[0]["app_id"] != "com.vettid.app.dev" {
		t.Fatalf("recorded: %+v", state)
	}
	// A vault that is not the dev stack's release is still refused.
	other := nsmtest.New(0x31, nil)
	if _, err := (&pushwire.Client{BaseURL: "http://" + pub, Attest: other.Attester()}).Register(ctx, key,
		pushwire.Registration{Platform: "fcm", Token: "t", AppID: "a"}); err == nil {
		t.Fatal("another PKI registered with the stand-in")
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "DEV STAND-IN") || !strings.Contains(out.String(), `"level":"WARN"`) {
		t.Fatalf("the stand-in did not announce itself: %s", out.String())
	}

	// The stand-in never takes the real AWS root: that would be a
	// gateway without a manifest.
	bad := cfg
	bad.DevNitroRoot = base64.StdEncoding.EncodeToString(attest.NitroRoot().Raw)
	if err := run(context.Background(), bad, deps{out: io.Discard, lookup: env(nil)}); err == nil || !strings.Contains(err.Error(), "TEST root") {
		t.Fatalf("-dev with the AWS root: %v", err)
	}
	bad.DevNitroRoot = "not base64"
	if err := run(context.Background(), bad, deps{out: io.Discard, lookup: env(nil)}); err == nil {
		t.Fatal("-dev with a malformed root started")
	}
}

// A channel that has published no manifest yet (production before its
// first release) starts, serves wakes and refuses registrations; a start
// with a missing or malformed secret fails without printing it.
func TestStartConditions(t *testing.T) {
	nsm := nsmtest.New(0xa0, nil)
	signer := nsmtest.NewManifestSigner()
	site := httptest.NewServer(http.NotFoundHandler())
	defer site.Close()
	blobKeys, _ := blob.NewSecret()
	cfg, err := config.Load(env(map[string]string{"PUSH_CHANNEL": "prod", "PUSH_LISTEN_ADDR": "127.0.0.1:0",
		"PUSH_PLATFORMS": "", "PUSH_SECRETS": "env"}), false)
	if err != nil {
		t.Fatal(err)
	}
	trust := &attest.Trust{ManifestURL: site.URL, ManifestKeys: signer.Keys()}
	out := &syncBuf{}
	// The env secret source, as a platform that injects secrets would
	// provide them.
	d := deps{out: out, lookup: env(map[string]string{"PUSH_SECRET_BLOB_KEYS": string(blobKeys)}), trust: trust, roots: nsm.Roots()}
	pub, _, stop := started(t, cfg, d)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	_, err = (&pushwire.Client{BaseURL: "http://" + pub, Attest: nsm.Attester()}).Register(context.Background(), key,
		pushwire.Registration{Platform: "apns", Token: strings.Repeat("ab", 32), AppID: "com.vettid.app", Environment: "production"})
	var ge *pushwire.Error
	if !errors.As(err, &ge) || ge.Status != 403 {
		t.Fatalf("registration without a manifest: %v", err)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out.String(), "no release manifest is published"); n != 1 {
		t.Fatalf("the missing manifest was reported %d times", n)
	}
	if strings.Contains(out.String(), `"level":"ERROR"`) {
		t.Fatalf("an unpublished manifest is not an error: %s", out.String())
	}

	// Missing and malformed secrets.
	cfg2, _ := config.Load(env(map[string]string{"PUSH_CHANNEL": "staging", "PUSH_LISTEN_ADDR": "127.0.0.1:0", "PUSH_SECRETS": "env",
		"PUSH_PLATFORMS": "apns", "PUSH_APNS_APP_IDS": "com.vettid.app.staging"}), false)
	for name, src := range map[string]secrets.Map{
		"no blob keys":        {},
		"malformed blob keys": {secrets.BlobKeys: []byte(`{"current":"zz","keys":{"zz":"SECRETSECRET"}}`)},
		"no apns secret":      {secrets.BlobKeys: blobKeys},
		"malformed apns":      {secrets.BlobKeys: blobKeys, secrets.APNs: []byte(`{"team_id":"T","key_id":"K","p8":"SECRETSECRET"}`)},
	} {
		err := run(context.Background(), cfg2, deps{out: io.Discard, lookup: env(nil), secrets: src, trust: trust, roots: nsm.Roots()})
		if err == nil || strings.Contains(err.Error(), "SECRETSECRET") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// §10.5: net/http's own error log names peer addresses ("http: TLS
// handshake error from 203.0.113.9:1234"); the gateway's server discards
// it.
func TestServerErrorLogIsDiscarded(t *testing.T) {
	srv := publicServer(http.NotFoundHandler())
	if srv.ErrorLog == nil || srv.ErrorLog.Writer() != io.Discard {
		t.Fatal("the HTTP server's error log is not discarded: it would log source addresses")
	}
	if srv.MaxHeaderBytes < 48<<10 {
		t.Fatal("the header limit is below a full attestation header")
	}
}

func TestHealthcheckCommand(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/health" {
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if code := runHealthcheck(config.Config{ListenAddr: ":" + port}); code != 0 {
		t.Fatalf("healthy gateway: exit %d", code)
	}
	srv.Close()
	if code := runHealthcheck(config.Config{ListenAddr: ":" + port}); code != 1 {
		t.Fatalf("no gateway: exit %d", code)
	}
	if !strings.Contains(buildVersion(), "PUSH-GATEWAY 0.4.5") {
		t.Fatal(buildVersion())
	}
}

// The gateway binary links no test support: no fake NSM, no test PKI.
func TestBinaryLinksNoTestSupport(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go tool")
	}
	outb, err := exec.Command(goBin, "list", "-deps", ".", "../pushctl").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, p := range strings.Fields(string(outb)) {
		if strings.Contains(p, "nsmtest") || strings.Contains(p, "enclavetest") || strings.Contains(p, "pushtest") ||
			p == "testing" || strings.HasSuffix(p, "/httptest") {
			t.Errorf("the binary links %s", p)
		}
	}
}
