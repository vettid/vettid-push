package provider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// APNs hosts (§6).
const (
	DefaultAPNsProductionURL = "https://api.push.apple.com"
	DefaultAPNsSandboxURL    = "https://api.sandbox.push.apple.com"
)

// The fixed APNs request (§6).
const (
	apnsPushType   = "alert"
	apnsPriority   = "10"
	apnsExpiration = 86400 * time.Second
)

// APNsPayload is the fixed APNs payload: byte-identical for every wake.
const APNsPayload = `{"aps":{"alert":{"loc-key":"WAKE_FALLBACK"},"mutable-content":1,"sound":"default"}}`

// Provider tokens: Apple refuses a token older than an hour and a token
// refreshed more often than every 20 minutes.
const (
	apnsTokenLife    = 45 * time.Minute
	apnsTokenMinLife = 20 * time.Minute
)

// ErrAPNsSecret is a malformed APNs secret.
var ErrAPNsSecret = errors.New("provider: malformed apns secret")

// APNsClient sends wakes through APNs with token-based (.p8) auth.
type APNsClient struct {
	teamID, keyID string
	key           *ecdsa.PrivateKey
	// ProductionURL and SandboxURL are the API bases (defaults: Apple's
	// hosts; tests point them at local fakes).
	ProductionURL, SandboxURL string
	// HTTP must speak HTTP/2, which APNs requires (NewAPNsHTTPClient).
	HTTP *http.Client
	Now  func() time.Time

	mu    sync.Mutex
	jwt   string
	jwtAt time.Time
}

type apnsSecret struct {
	TeamID string `json:"team_id"`
	KeyID  string `json:"key_id"`
	P8     string `json:"p8"`
}

func alnum(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// NewAPNsClient builds a client from the APNs secret (§10.2): {team_id,
// key_id, p8}, the .p8 being Apple's PKCS #8 PEM of a P-256 key.
func NewAPNsClient(secret []byte) (*APNsClient, error) {
	var s apnsSecret
	if err := json.Unmarshal(secret, &s); err != nil || !alnum(s.TeamID, 10) || !alnum(s.KeyID, 10) {
		return nil, ErrAPNsSecret
	}
	blk, _ := pem.Decode([]byte(s.P8))
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, ErrAPNsSecret
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, ErrAPNsSecret
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, ErrAPNsSecret
	}
	return &APNsClient{teamID: s.TeamID, keyID: s.KeyID, key: key, HTTP: NewAPNsHTTPClient(nil)}, nil
}

// NewAPNsHTTPClient returns an HTTP/2 client for APNs with long-lived
// connections (Apple asks providers to keep them open). roots, if set,
// replace the system roots (tests).
func NewAPNsHTTPClient(roots *x509.CertPool) *http.Client {
	return &http.Client{Transport: &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Minute,
		TLSHandshakeTimeout: 5 * time.Second,
	}}
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// providerToken returns the cached ES256 JWT, minting a new one when the
// cached one is older than apnsTokenLife or renew is set and Apple's
// minimum refresh interval has passed.
func (c *APNsClient) providerToken(now time.Time, renew bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	age := now.Sub(c.jwtAt)
	if c.jwt != "" && age >= 0 && age < apnsTokenLife && !(renew && age >= apnsTokenMinLife) {
		return c.jwt, nil
	}
	head, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": c.keyID})
	claims, _ := json.Marshal(map[string]any{"iss": c.teamID, "iat": now.Unix()})
	signing := b64url(head) + "." + b64url(claims)
	d := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, d[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	c.jwt, c.jwtAt = signing+"."+b64url(sig), now
	return c.jwt, nil
}

// apnsReasons are the reasons APNs documents.
var apnsReasons = []string{"BadCollapseId", "BadDeviceToken", "BadExpirationDate", "BadMessageId", "BadPriority",
	"BadTopic", "DeviceTokenNotForTopic", "DuplicateHeaders", "IdleTimeout", "InvalidPushType", "MissingDeviceToken",
	"MissingTopic", "PayloadEmpty", "TopicDisallowed", "BadCertificate", "BadCertificateEnvironment",
	"ExpiredProviderToken", "Forbidden", "InvalidProviderToken", "MissingProviderToken", "UnrelatedKeyIdInToken",
	"BadEnvironmentKeyIdInToken", "BadPath", "MethodNotAllowed", "ExpiredToken", "Unregistered", "PayloadTooLarge",
	"TooManyProviderTokenUpdates", "TooManyRequests", "InternalServerError", "ServiceUnavailable", "Shutdown"}

// Send implements Provider.
func (c *APNsClient) Send(ctx context.Context, m Message) Result {
	ctx, cancel := context.WithTimeout(ctx, SendTimeout)
	defer cancel()
	r := c.send(ctx, m, false)
	if r.Outcome == AuthFailed && r.Detail == "ExpiredProviderToken" {
		// Our clock or Apple's moved: mint a new token (if Apple's
		// refresh interval allows) and try once more.
		r = c.send(ctx, m, true)
	}
	return r
}

func (c *APNsClient) send(ctx context.Context, m Message, renew bool) Result {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	base := c.ProductionURL
	if base == "" {
		base = DefaultAPNsProductionURL
	}
	switch m.Environment {
	case EnvProduction:
	case EnvSandbox:
		if base = c.SandboxURL; base == "" {
			base = DefaultAPNsSandboxURL
		}
	default:
		return Result{Outcome: Rejected, Detail: "environment"}
	}
	jwt, err := c.providerToken(now(), renew)
	if err != nil {
		return Result{Outcome: AuthFailed, Detail: "provider_token"}
	}
	// The token is 64-200 lowercase hex digits (checked at registration,
	// and again by the caller after the blob opens): safe in a path.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/3/device/"+m.Token, bytes.NewReader([]byte(APNsPayload)))
	if err != nil {
		return Result{Outcome: Rejected, Detail: "request"}
	}
	req.Header.Set("authorization", "bearer "+jwt)
	req.Header.Set("apns-push-type", apnsPushType)
	req.Header.Set("apns-priority", apnsPriority)
	req.Header.Set("apns-topic", m.AppID)
	req.Header.Set("apns-expiration", strconv.FormatInt(now().Add(apnsExpiration).Unix(), 10))
	req.Header.Set("content-type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Result{Outcome: Unavailable, Detail: transportDetail(ctx)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode == http.StatusOK {
		return Result{Outcome: Sent}
	}
	var e struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(body, &e)
	detail := pick(e.Reason, apnsReasons, "other")
	ra := retryAfter(resp.Header, now())
	switch {
	case resp.StatusCode == http.StatusGone:
		return Result{Outcome: TokenGone, Detail: detail}
	case e.Reason == "BadDeviceToken" || e.Reason == "DeviceTokenNotForTopic":
		// DeviceTokenNotForTopic: the token is another app's. Like a bad
		// token, only a new registration can help.
		return Result{Outcome: TokenInvalid, Detail: detail}
	case resp.StatusCode == http.StatusForbidden:
		return Result{Outcome: AuthFailed, Detail: detail}
	case resp.StatusCode == http.StatusTooManyRequests:
		return Result{Outcome: RateLimited, RetryAfter: ra, Detail: detail}
	case resp.StatusCode >= 500:
		return Result{Outcome: Unavailable, RetryAfter: ra, Detail: detail}
	}
	return Result{Outcome: Rejected, Detail: detail}
}
