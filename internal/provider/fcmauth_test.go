package provider

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }
func newClock() *clock               { return &clock{t: t0} }
func b64dec(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// serviceAccountKey returns a service-account JSON key around a fresh
// RSA key (generated here; no real key is a fixture).
func serviceAccountKey(t *testing.T) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	b, _ := json.Marshal(map[string]string{
		"type": "service_account", "project_id": "vettid-staging", "private_key_id": "kid-1",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email": "vettid-push@vettid-staging.iam.gserviceaccount.com",
		"token_uri":    "https://oauth2.googleapis.com/token",
	})
	return b, key
}

// §10.3 fallback: the service-account JSON key. The JWT bearer grant is
// signed RS256 for the firebase.messaging scope; the access token is
// cached and renewed before it expires.
func TestServiceAccountKey(t *testing.T) {
	secret, key := serviceAccountKey(t)
	clk := newClock()
	var mu sync.Mutex
	grants := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		grants++
		if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("grant: %v", r.Form)
		}
		parts := strings.Split(r.Form.Get("assertion"), ".")
		if len(parts) != 3 {
			t.Errorf("assertion has %d parts", len(parts))
			w.WriteHeader(400)
			return
		}
		var head map[string]string
		var claims map[string]any
		_ = json.Unmarshal(b64dec(t, parts[0]), &head)
		_ = json.Unmarshal(b64dec(t, parts[1]), &claims)
		d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, d[:], b64dec(t, parts[2])); err != nil {
			t.Errorf("JWT signature: %v", err)
		}
		if head["alg"] != "RS256" || head["kid"] != "kid-1" {
			t.Errorf("JWT header %v", head)
		}
		iat, exp := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
		if claims["iss"] != "vettid-push@vettid-staging.iam.gserviceaccount.com" ||
			claims["scope"] != "https://www.googleapis.com/auth/firebase.messaging" ||
			claims["aud"] != "https://oauth2.googleapis.com/token" || iat != clk.now().Unix() || exp-iat != 3600 {
			t.Errorf("JWT claims %v", claims)
		}
		_, _ = w.Write([]byte(`{"access_token":"ya29.grant` + string(rune('0'+grants)) + `","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	ts, kind, project, err := NewFCMTokenSource(secret, FCMAuthOptions{Now: clk.now, OAuthTokenURL: srv.URL})
	if err != nil || kind != FCMServiceAccount || project != "vettid-staging" {
		t.Fatalf("kind %s project %s err %v", kind, project, err)
	}
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if tok, err := ts.Token(ctx); err != nil || tok != "ya29.grant1" {
			t.Fatalf("token %q err %v", tok, err)
		}
	}
	clk.add(54 * time.Minute)
	if tok, _ := ts.Token(ctx); tok != "ya29.grant1" || grants != 1 {
		t.Fatalf("renewed too early: %s after %d grants", tok, grants)
	}
	clk.add(2 * time.Minute) // inside the 5-minute margin
	if tok, _ := ts.Token(ctx); tok != "ya29.grant2" {
		t.Fatalf("not renewed before expiry: %s", tok)
	}
	ts.Invalidate()
	if tok, _ := ts.Token(ctx); tok != "ya29.grant3" {
		t.Fatalf("not fetched again after Invalidate: %s", tok)
	}
}

// A token endpoint that refuses: no token, no hammering, and the answer
// is not repeated in the error.
func TestTokenFetchFailure(t *testing.T) {
	secret, _ := serviceAccountKey(t)
	clk := newClock()
	var mu sync.Mutex
	calls, fail := 0, true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if fail {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"SECRET detail"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"ok","expires_in":3600}`))
	}))
	defer srv.Close()
	ts, _, _, err := NewFCMTokenSource(secret, FCMAuthOptions{Now: clk.now, OAuthTokenURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		if _, err := ts.Token(ctx); err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Fatalf("err %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("%d token requests for 10 wakes within the pause", calls)
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	clk.add(6 * time.Second)
	if tok, err := ts.Token(ctx); err != nil || tok != "ok" {
		t.Fatalf("after the pause: %q %v", tok, err)
	}
}

const federationSecret = `{
  "type": "external_account",
  "audience": "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/vettid-aws/providers/vettid-main",
  "subject_token_type": "urn:ietf:params:aws:token-type:aws4_request",
  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/vettid-push@vettid-staging.iam.gserviceaccount.com:generateAccessToken",
  "token_url": "https://sts.googleapis.com/v1/token",
  "credential_source": {
    "environment_id": "aws1",
    "region_url": "http://169.254.169.254/latest/meta-data/placement/availability-zone",
    "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials",
    "regional_cred_verification_url": "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15"
  }
}`

func hm(key []byte, s string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(s))
	return h.Sum(nil)
}
func hexsum(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// sigV4 recomputes an AWS Signature Version 4 from first principles, the
// way AWS STS will when Google forwards the request.
func sigV4(secretKey, region, amzDate string, headers map[string]string, signed []string) string {
	var canon strings.Builder
	canon.WriteString("POST\n/\nAction=GetCallerIdentity&Version=2011-06-15\n")
	for _, h := range signed {
		canon.WriteString(h + ":" + headers[h] + "\n")
	}
	canon.WriteString("\n" + strings.Join(signed, ";") + "\n" + hexsum(""))
	date := amzDate[:8]
	scope := date + "/" + region + "/sts/aws4_request"
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hexsum(canon.String())
	k := hm(hm(hm(hm([]byte("AWS4"+secretKey), date), region), "sts"), "aws4_request")
	return hex.EncodeToString(hm(k, sts))
}

// §10.3: workload identity federation for AWS. The gateway's role
// credentials sign a GetCallerIdentity request (the subject token);
// Google's STS exchanges it; the federated token impersonates the
// service account for the firebase.messaging scope. No Google key
// exists.
func TestWorkloadIdentityFederation(t *testing.T) {
	clk := newClock()
	// Throwaway credentials in AWS's shape, made up here.
	creds := aws.Credentials{AccessKeyID: "ASIATESTTESTTESTTEST", SecretAccessKey: "test-secret-access-key/not-real", SessionToken: "test-session-token"}
	const audience = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/vettid-aws/providers/vettid-main"
	var mu sync.Mutex
	var exchanges, impersonations int
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/token", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		exchanges++
		_ = r.ParseForm()
		for k, want := range map[string]string{
			"grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
			"audience":             audience,
			"scope":                "https://www.googleapis.com/auth/cloud-platform",
			"requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"subject_token_type":   "urn:ietf:params:aws:token-type:aws4_request",
		} {
			if r.Form.Get(k) != want {
				t.Errorf("exchange %s = %q", k, r.Form.Get(k))
			}
		}
		raw, err := url.QueryUnescape(r.Form.Get("subject_token"))
		if err != nil {
			t.Errorf("subject token: %v", err)
		}
		var st struct {
			URL     string `json:"url"`
			Method  string `json:"method"`
			Headers []struct{ Key, Value string }
		}
		if err := json.Unmarshal([]byte(raw), &st); err != nil {
			t.Errorf("subject token JSON: %v", err)
		}
		if st.URL != "https://sts.us-east-1.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15" || st.Method != "POST" {
			t.Errorf("subject token request %s %s", st.Method, st.URL)
		}
		h := map[string]string{}
		for _, kv := range st.Headers {
			h[strings.ToLower(kv.Key)] = kv.Value
		}
		if h["host"] != "sts.us-east-1.amazonaws.com" || h["x-goog-cloud-target-resource"] != audience ||
			h["x-amz-security-token"] != "test-session-token" || h["x-amz-date"] != clk.now().UTC().Format("20060102T150405Z") {
			t.Errorf("subject token headers %v", h)
		}
		m := regexp.MustCompile(`^AWS4-HMAC-SHA256 Credential=ASIATESTTESTTESTTEST/(\d{8})/us-east-1/sts/aws4_request, SignedHeaders=([a-z0-9;-]+), Signature=([0-9a-f]{64})$`).FindStringSubmatch(h["authorization"])
		if m == nil {
			t.Errorf("Authorization %q", h["authorization"])
			w.WriteHeader(400)
			return
		}
		signed := strings.Split(m[2], ";")
		// AWS verifies over the signed headers: each must be among the
		// headers Google forwards, and the target resource (which binds
		// the token to this pool) must be signed.
		bound := false
		for _, s := range signed {
			if _, ok := h[s]; !ok {
				t.Errorf("signed header %q is not in the subject token", s)
			}
			bound = bound || s == "x-goog-cloud-target-resource"
		}
		if !bound {
			t.Error("x-goog-cloud-target-resource is not signed")
		}
		if want := sigV4(creds.SecretAccessKey, "us-east-1", h["x-amz-date"], h, signed); m[3] != want {
			t.Errorf("SigV4 signature %s, recomputed %s", m[3], want)
		}
		_, _ = w.Write([]byte(`{"access_token":"federated-token","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}`))
	})
	mux.HandleFunc("POST /v1/projects/-/serviceAccounts/vettid-push@vettid-staging.iam.gserviceaccount.com:generateAccessToken", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		impersonations++
		if r.Header.Get("Authorization") != "Bearer federated-token" {
			t.Errorf("impersonation bearer %q", r.Header.Get("Authorization"))
		}
		var in struct {
			Scope    []string `json:"scope"`
			Lifetime string   `json:"lifetime"`
		}
		b, _ := io.ReadAll(r.Body)
		if json.Unmarshal(b, &in) != nil || len(in.Scope) != 1 || in.Scope[0] != "https://www.googleapis.com/auth/firebase.messaging" {
			t.Errorf("impersonation body %s", b)
		}
		_, _ = w.Write([]byte(`{"accessToken":"ya29.impersonated","expireTime":"` + clk.now().Add(time.Hour).UTC().Format(time.RFC3339) + `"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	o := FCMAuthOptions{Now: clk.now, Region: "us-east-1", STSTokenURL: srv.URL + "/v1/token", IAMCredentialsBase: srv.URL,
		AWSCredentials: func(context.Context) (aws.Credentials, error) { return creds, nil }}
	ts, kind, project, err := NewFCMTokenSource([]byte(federationSecret), o)
	if err != nil || kind != FCMFederation || project != "" {
		t.Fatalf("kind %s project %q err %v", kind, project, err)
	}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if tok, err := ts.Token(ctx); err != nil || tok != "ya29.impersonated" {
			t.Fatalf("token %q err %v", tok, err)
		}
	}
	if exchanges != 1 || impersonations != 1 {
		t.Fatalf("%d exchanges, %d impersonations for three sends", exchanges, impersonations)
	}
	clk.add(56 * time.Minute)
	if _, err := ts.Token(ctx); err != nil || exchanges != 2 {
		t.Fatalf("not renewed before expiry: %v, %d exchanges", err, exchanges)
	}

	// End to end with the FCM client.
	fake := &fcmFake{}
	fsrv := httptest.NewServer(fake)
	defer fsrv.Close()
	c := &FCMClient{Project: "vettid-staging", Tokens: ts, BaseURL: fsrv.URL}
	if r := c.Send(ctx, Message{Token: "t"}); r.Outcome != Sent || fake.reqs[0].Header.Get("Authorization") != "Bearer ya29.impersonated" {
		t.Fatalf("%+v", r)
	}

	// Without role credentials: no token, an auth failure.
	o.AWSCredentials = func(context.Context) (aws.Credentials, error) { return aws.Credentials{}, errors.New("no role") }
	ts2, _, _, _ := NewFCMTokenSource([]byte(federationSecret), o)
	if _, err := ts2.Token(ctx); err == nil {
		t.Fatal("a token without AWS credentials")
	}
}

// The secret's content selects the access kind, and only Google's own
// endpoints are accepted inside it: a secret cannot redirect the
// gateway's credentials to another host.
func TestFCMSecretValidation(t *testing.T) {
	sa, _ := serviceAccountKey(t)
	awsOK := FCMAuthOptions{Region: "us-east-1", AWSCredentials: func(context.Context) (aws.Credentials, error) { return aws.Credentials{}, nil }}
	edit := func(src []byte, f func(map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(src, &m)
		f(m)
		b, _ := json.Marshal(m)
		return b
	}
	fed := []byte(federationSecret)
	bad := map[string][]byte{
		"not JSON":            []byte("nope"),
		"empty object":        []byte("{}"),
		"authorized_user":     []byte(`{"type":"authorized_user","refresh_token":"x"}`),
		"sa: other token uri": edit(sa, func(m map[string]any) { m["token_uri"] = "https://evil.example/token" }),
		"sa: no email":        edit(sa, func(m map[string]any) { delete(m, "client_email") }),
		"sa: no key":          edit(sa, func(m map[string]any) { m["private_key"] = "" }),
		"fed: other sts":      edit(fed, func(m map[string]any) { m["token_url"] = "https://sts.evil.example/v1/token" }),
		"fed: other impersonation host": edit(fed, func(m map[string]any) {
			m["service_account_impersonation_url"] = "https://evil.example/v1/projects/-/serviceAccounts/a@b:generateAccessToken"
		}),
		"fed: no impersonation": edit(fed, func(m map[string]any) { delete(m, "service_account_impersonation_url") }),
		"fed: not aws":          edit(fed, func(m map[string]any) { m["subject_token_type"] = "urn:ietf:params:oauth:token-type:jwt" }),
		"fed: other verification url": edit(fed, func(m map[string]any) {
			m["credential_source"].(map[string]any)["regional_cred_verification_url"] = "https://evil.example?Action=GetCallerIdentity"
		}),
		"fed: bad audience": edit(fed, func(m map[string]any) { m["audience"] = "//evil.example/pool" }),
	}
	for name, s := range bad {
		if _, _, _, err := NewFCMTokenSource(s, awsOK); !errors.Is(err, ErrFCMSecret) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, _, err := NewFCMTokenSource(fed, FCMAuthOptions{}); err == nil || errors.Is(err, ErrFCMSecret) {
		t.Errorf("federation without AWS credentials: %v", err)
	}
	if _, kind, _, err := NewFCMTokenSource(fed, awsOK); err != nil || kind != FCMFederation {
		t.Errorf("federation: %v", err)
	}
	if _, kind, project, err := NewFCMTokenSource(sa, FCMAuthOptions{}); err != nil || kind != FCMServiceAccount || project != "vettid-staging" {
		t.Errorf("service account: %v", err)
	}
	// A project_id added to the federation config is read too.
	withProject := edit(fed, func(m map[string]any) { m["project_id"] = "vettid-prod" })
	if _, _, project, err := NewFCMTokenSource(withProject, awsOK); err != nil || project != "vettid-prod" {
		t.Errorf("federation with project_id: %q %v", project, err)
	}
}
