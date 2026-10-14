package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// DefaultFCMBaseURL is the FCM HTTP v1 endpoint.
const DefaultFCMBaseURL = "https://fcm.googleapis.com"

// FCMClient sends wakes through FCM HTTP v1 `messages:send`.
type FCMClient struct {
	// Project is the channel's Firebase project id.
	Project string
	// Tokens yields OAuth 2.0 access tokens with the
	// firebase.messaging scope.
	Tokens TokenSource
	// BaseURL is the API base (default DefaultFCMBaseURL; tests point it
	// at a local fake).
	BaseURL string
	HTTP    *http.Client
	Now     func() time.Time
}

// fcmMessage is the fixed FCM payload (§6): a data message only.
type fcmMessage struct {
	Message struct {
		Token   string            `json:"token"`
		Data    map[string]string `json:"data"`
		Android struct {
			Priority    string `json:"priority"`
			CollapseKey string `json:"collapse_key"`
			TTL         string `json:"ttl"`
		} `json:"android"`
	} `json:"message"`
}

// FCMPayload returns the request body for a token: identical for every
// wake apart from the token.
func FCMPayload(token string) []byte {
	var m fcmMessage
	m.Message.Token = token
	m.Message.Data = map[string]string{"w": "1"}
	m.Message.Android.Priority = "HIGH"
	m.Message.Android.CollapseKey = "w"
	m.Message.Android.TTL = "86400s"
	return encodeFCM(m)
}

// FCMChallengePayload returns the request body of a registration's token
// challenge (§6): a data message whose only member is the code, under
// its own collapse key, kept by Google no longer than the challenge is
// valid.
func FCMChallengePayload(token, code string) []byte {
	var m fcmMessage
	m.Message.Token = token
	m.Message.Data = map[string]string{"c": code}
	m.Message.Android.Priority = "HIGH"
	m.Message.Android.CollapseKey = "c"
	m.Message.Android.TTL = strconv.Itoa(int(ChallengeLife/time.Second)) + "s"
	return encodeFCM(m)
}

func encodeFCM(m fcmMessage) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(m)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

// fcmError is the error body of the Google APIs.
type fcmError struct {
	Error struct {
		Code    int    `json:"code"`
		Status  string `json:"status"`
		Details []struct {
			Type      string `json:"@type"`
			ErrorCode string `json:"errorCode"`
		} `json:"details"`
	} `json:"error"`
}

// fcmCodes are the FCM v1 ErrorCode values and the google.rpc statuses
// that accompany them.
var fcmCodes = []string{"UNREGISTERED", "INVALID_ARGUMENT", "SENDER_ID_MISMATCH", "QUOTA_EXCEEDED",
	"UNAVAILABLE", "INTERNAL", "THIRD_PARTY_AUTH_ERROR", "UNSPECIFIED_ERROR",
	"NOT_FOUND", "PERMISSION_DENIED", "UNAUTHENTICATED", "RESOURCE_EXHAUSTED"}

// Send implements Provider.
func (c *FCMClient) Send(ctx context.Context, m Message) Result {
	ctx, cancel := context.WithTimeout(ctx, SendTimeout)
	defer cancel()
	r := c.send(ctx, m)
	if r.Outcome == AuthFailed && r.Detail == "UNAUTHENTICATED" {
		// The cached access token was refused: fetch a new one, once.
		c.Tokens.Invalidate()
		r = c.send(ctx, m)
	}
	return r
}

func (c *FCMClient) send(ctx context.Context, m Message) Result {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	tok, err := c.Tokens.Token(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return Result{Outcome: Unavailable, Detail: "timeout"}
		}
		return Result{Outcome: AuthFailed, Detail: "access_token"}
	}
	base := c.BaseURL
	if base == "" {
		base = DefaultFCMBaseURL
	}
	payload := FCMPayload(m.Token)
	if m.Challenge != "" {
		if !challengeCode(m.Challenge) {
			return Result{Outcome: Rejected, Detail: "request"}
		}
		payload = FCMChallengePayload(m.Token, m.Challenge)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/v1/projects/"+url.PathEscape(c.Project)+"/messages:send", bytes.NewReader(payload))
	if err != nil {
		return Result{Outcome: Rejected, Detail: "request"}
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return Result{Outcome: Unavailable, Detail: transportDetail(ctx)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if resp.StatusCode == http.StatusOK {
		return Result{Outcome: Sent}
	}
	var e fcmError
	_ = json.Unmarshal(body, &e)
	code := e.Error.Status
	for _, d := range e.Error.Details {
		if d.ErrorCode != "" {
			code = d.ErrorCode
		}
	}
	detail := pick(code, fcmCodes, "other")
	ra := retryAfter(resp.Header, now())
	switch {
	case code == "UNREGISTERED" || resp.StatusCode == http.StatusNotFound:
		return Result{Outcome: TokenGone, Detail: detail}
	case code == "SENDER_ID_MISMATCH":
		// The token belongs to another Firebase project: it can never
		// work here. Handled as a bad token, not as an auth failure.
		return Result{Outcome: TokenInvalid, Detail: detail}
	case code == "INVALID_ARGUMENT" || resp.StatusCode == http.StatusBadRequest:
		return Result{Outcome: TokenInvalid, Detail: detail}
	case resp.StatusCode == http.StatusUnauthorized:
		return Result{Outcome: AuthFailed, Detail: "UNAUTHENTICATED"}
	case resp.StatusCode == http.StatusForbidden:
		return Result{Outcome: AuthFailed, Detail: detail}
	case code == "QUOTA_EXCEEDED" || resp.StatusCode == http.StatusTooManyRequests:
		return Result{Outcome: RateLimited, RetryAfter: ra, Detail: detail}
	case resp.StatusCode >= 500:
		return Result{Outcome: Unavailable, RetryAfter: ra, Detail: detail}
	}
	return Result{Outcome: Rejected, Detail: detail}
}

func transportDetail(ctx context.Context) string {
	if ctx.Err() != nil {
		return "timeout"
	}
	return "transport"
}
