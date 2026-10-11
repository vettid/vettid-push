package provider

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// Google endpoints and constants of the two FCM credential kinds
// (PUSH-GATEWAY §10.3).
const (
	fcmScope             = "https://www.googleapis.com/auth/firebase.messaging"
	cloudPlatformScope   = "https://www.googleapis.com/auth/cloud-platform"
	googleOAuthTokenURL  = "https://oauth2.googleapis.com/token"
	googleSTSTokenURL    = "https://sts.googleapis.com/v1/token"
	googleIAMCredentials = "https://iamcredentials.googleapis.com"
	awsSubjectTokenType  = "urn:ietf:params:aws:token-type:aws4_request"
	awsVerificationURL   = "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15"
	emptySHA256          = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// ErrFCMSecret is a malformed or unsupported FCM secret.
var ErrFCMSecret = errors.New("provider: malformed fcm secret")

// errToken is a failed access-token fetch (no detail: Google's answers
// are not repeated).
var errToken = errors.New("provider: access token unavailable")

// TokenSource yields OAuth 2.0 access tokens for FCM.
type TokenSource interface {
	// Token returns a valid access token, fetching one when needed.
	Token(ctx context.Context) (string, error)
	// Invalidate drops the cached token (the API refused it).
	Invalidate()
}

// FCMAuthOptions configures the FCM token source.
type FCMAuthOptions struct {
	// HTTP calls Google's token endpoints (default: a client with a 5 s
	// timeout).
	HTTP *http.Client
	Now  func() time.Time
	// AWSCredentials returns the gateway's AWS role credentials and
	// Region its region; needed for workload identity federation only.
	AWSCredentials func(context.Context) (aws.Credentials, error)
	Region         string
	// Test endpoints: when set they replace Google's hosts. Production
	// code leaves them empty, and the URLs inside the secret must then
	// be exactly Google's.
	OAuthTokenURL      string
	STSTokenURL        string
	IAMCredentialsBase string
}

// FCMKind names the credential kind of an FCM secret.
type FCMKind string

// Kinds.
const (
	FCMFederation     FCMKind = "workload_identity_federation"
	FCMServiceAccount FCMKind = "service_account_key"
)

type fcmSecret struct {
	Type      string `json:"type"`
	ProjectID string `json:"project_id"`

	// service_account
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	TokenURI     string `json:"token_uri"`

	// external_account (workload identity federation for AWS)
	Audience         string `json:"audience"`
	SubjectTokenType string `json:"subject_token_type"`
	TokenURL         string `json:"token_url"`
	ImpersonationURL string `json:"service_account_impersonation_url"`
	CredentialSource struct {
		EnvironmentID   string `json:"environment_id"`
		VerificationURL string `json:"regional_cred_verification_url"`
	} `json:"credential_source"`
}

var (
	impersonationRE = regexp.MustCompile(`^https://iamcredentials\.googleapis\.com(/v1/projects/-/serviceAccounts/[A-Za-z0-9._@-]+:generateAccessToken)$`)
	audienceRE      = regexp.MustCompile(`^//iam\.googleapis\.com/projects/[0-9]+/locations/global/workloadIdentityPools/[a-z0-9-]+/providers/[a-z0-9-]+$`)
	regionRE        = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)
)

// NewFCMTokenSource builds the token source the secret's content selects
// (§10.2): Google's `external_account` configuration for workload
// identity federation with AWS (no secret inside; recommended), or a
// `service_account` JSON key (the fallback). It also returns the
// secret's project_id, if it has one. Nothing is fetched yet.
func NewFCMTokenSource(secret []byte, o FCMAuthOptions) (TokenSource, FCMKind, string, error) {
	var s fcmSecret
	if err := json.Unmarshal(secret, &s); err != nil {
		return nil, "", "", ErrFCMSecret
	}
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: SendTimeout}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	switch s.Type {
	case "service_account":
		blk, _ := pem.Decode([]byte(s.PrivateKey))
		if blk == nil || s.ClientEmail == "" || s.TokenURI != googleOAuthTokenURL {
			return nil, "", "", ErrFCMSecret
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, "", "", ErrFCMSecret
		}
		key, ok := k.(*rsa.PrivateKey)
		if !ok || key.N.BitLen() < 2048 {
			return nil, "", "", ErrFCMSecret
		}
		tokenURL := googleOAuthTokenURL
		if o.OAuthTokenURL != "" {
			tokenURL = o.OAuthTokenURL
		}
		src := &serviceAccountSource{o: o, key: key, keyID: s.PrivateKeyID, email: s.ClientEmail, tokenURL: tokenURL}
		return newCachedSource(src.fetch, o.Now), FCMServiceAccount, s.ProjectID, nil
	case "external_account":
		m := impersonationRE.FindStringSubmatch(s.ImpersonationURL)
		if m == nil || !audienceRE.MatchString(s.Audience) || s.SubjectTokenType != awsSubjectTokenType ||
			s.TokenURL != googleSTSTokenURL || s.CredentialSource.EnvironmentID != "aws1" ||
			s.CredentialSource.VerificationURL != awsVerificationURL {
			return nil, "", "", ErrFCMSecret
		}
		if o.AWSCredentials == nil || !regionRE.MatchString(o.Region) {
			return nil, "", "", errors.New("provider: fcm workload identity federation needs AWS credentials and a region")
		}
		src := &federationSource{o: o, audience: s.Audience, stsURL: googleSTSTokenURL, impersonationURL: s.ImpersonationURL}
		if o.STSTokenURL != "" {
			src.stsURL = o.STSTokenURL
		}
		if o.IAMCredentialsBase != "" {
			src.impersonationURL = o.IAMCredentialsBase + m[1]
		}
		return newCachedSource(src.fetch, o.Now), FCMFederation, s.ProjectID, nil
	}
	return nil, "", "", ErrFCMSecret
}

// cachedSource caches an access token until shortly before it expires.
type cachedSource struct {
	fetch func(context.Context) (string, time.Time, error)
	now   func() time.Time

	mu       sync.Mutex
	token    string
	expires  time.Time
	failedAt time.Time
}

const (
	tokenRefreshMargin = 5 * time.Minute
	// tokenRetryPause spaces out fetches while Google refuses, so that
	// a misconfiguration does not turn every wake into a token request.
	tokenRetryPause = 5 * time.Second
)

func newCachedSource(fetch func(context.Context) (string, time.Time, error), now func() time.Time) *cachedSource {
	return &cachedSource{fetch: fetch, now: now}
}

func (c *cachedSource) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.token != "" && now.Before(c.expires.Add(-tokenRefreshMargin)) {
		return c.token, nil
	}
	if !c.failedAt.IsZero() && now.Sub(c.failedAt) < tokenRetryPause && now.Sub(c.failedAt) >= 0 {
		if c.token != "" && now.Before(c.expires) {
			return c.token, nil
		}
		return "", errToken
	}
	tok, exp, err := c.fetch(ctx)
	if err != nil || tok == "" {
		c.failedAt = now
		if c.token != "" && now.Before(c.expires) {
			return c.token, nil // still valid: use it while the refresh fails
		}
		return "", errToken
	}
	c.token, c.expires, c.failedAt = tok, exp, time.Time{}
	return tok, nil
}

func (c *cachedSource) Invalidate() {
	c.mu.Lock()
	c.token, c.expires = "", time.Time{}
	c.mu.Unlock()
}

// postJSON posts body and decodes a 200 JSON answer of at most 64 KiB.
func postJSON(ctx context.Context, hc *http.Client, u, contentType, bearer string, body string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(body))
	if err != nil {
		return errToken
	}
	req.Header.Set("Content-Type", contentType)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return errToken
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil || resp.StatusCode != http.StatusOK || json.Unmarshal(b, out) != nil {
		return errToken
	}
	return nil
}

type oauthToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

// serviceAccountSource: the JWT bearer grant (RFC 7523) with the
// service account's RSA key.
type serviceAccountSource struct {
	o        FCMAuthOptions
	key      *rsa.PrivateKey
	keyID    string
	email    string
	tokenURL string
}

func (s *serviceAccountSource) fetch(ctx context.Context) (string, time.Time, error) {
	now := s.o.Now()
	head, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": s.keyID})
	// aud is always Google's token endpoint, whatever endpoint a test
	// posts to.
	claims, _ := json.Marshal(map[string]any{"iss": s.email, "scope": fcmScope, "aud": googleOAuthTokenURL,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	signing := b64url(head) + "." + b64url(claims)
	d := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, d[:])
	if err != nil {
		return "", time.Time{}, errToken
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {signing + "." + b64url(sig)}}
	var t oauthToken
	if err := postJSON(ctx, s.o.HTTP, s.tokenURL, "application/x-www-form-urlencoded", "", form.Encode(), &t); err != nil {
		return "", time.Time{}, err
	}
	return t.AccessToken, now.Add(time.Duration(t.ExpiresIn) * time.Second), nil
}

// federationSource: workload identity federation for AWS. The gateway's
// role credentials sign an STS GetCallerIdentity request, which is the
// subject token; Google's STS exchanges it for a federated token, which
// then impersonates the service account. No Google key exists anywhere.
type federationSource struct {
	o                FCMAuthOptions
	audience         string
	stsURL           string
	impersonationURL string
}

type awsHeader struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// subjectToken serializes a signed GetCallerIdentity request the way
// Google's STS expects it (the `aws4_request` subject token).
func (f *federationSource) subjectToken(ctx context.Context, now time.Time) (string, error) {
	creds, err := f.o.AWSCredentials(ctx)
	if err != nil {
		return "", errToken
	}
	target := strings.Replace(awsVerificationURL, "{region}", f.o.Region, 1)
	req, err := http.NewRequest(http.MethodPost, target, nil)
	if err != nil {
		return "", errToken
	}
	req.Header.Set("x-goog-cloud-target-resource", f.audience)
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, emptySHA256, "sts", f.o.Region, now); err != nil {
		return "", errToken
	}
	hdrs := []awsHeader{{"Authorization", req.Header.Get("Authorization")}, {"host", req.URL.Host},
		{"x-amz-date", req.Header.Get("X-Amz-Date")}, {"x-goog-cloud-target-resource", f.audience}}
	if st := req.Header.Get("X-Amz-Security-Token"); st != "" {
		hdrs = append(hdrs, awsHeader{"x-amz-security-token", st})
	}
	b, err := json.Marshal(struct {
		URL     string      `json:"url"`
		Method  string      `json:"method"`
		Headers []awsHeader `json:"headers"`
	}{target, http.MethodPost, hdrs})
	if err != nil {
		return "", errToken
	}
	return url.QueryEscape(string(b)), nil
}

func (f *federationSource) fetch(ctx context.Context) (string, time.Time, error) {
	now := f.o.Now()
	subject, err := f.subjectToken(ctx, now)
	if err != nil {
		return "", time.Time{}, err
	}
	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"audience":             {f.audience},
		"scope":                {cloudPlatformScope},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"subject_token_type":   {awsSubjectTokenType},
		"subject_token":        {subject},
	}
	var fed oauthToken
	if err := postJSON(ctx, f.o.HTTP, f.stsURL, "application/x-www-form-urlencoded", "", form.Encode(), &fed); err != nil || fed.AccessToken == "" {
		return "", time.Time{}, errToken
	}
	var imp struct {
		AccessToken string `json:"accessToken"`
		ExpireTime  string `json:"expireTime"`
	}
	body, _ := json.Marshal(map[string]any{"scope": []string{fcmScope}, "lifetime": "3600s"})
	if err := postJSON(ctx, f.o.HTTP, f.impersonationURL, "application/json", fed.AccessToken, string(body), &imp); err != nil {
		return "", time.Time{}, err
	}
	exp, err := time.Parse(time.RFC3339, imp.ExpireTime)
	if err != nil {
		return "", time.Time{}, errToken
	}
	return imp.AccessToken, exp, nil
}
