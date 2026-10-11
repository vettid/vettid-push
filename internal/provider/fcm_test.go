package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

// staticTokens is a TokenSource with a fixed sequence of tokens.
type staticTokens struct {
	mu          sync.Mutex
	tokens      []string
	invalidated int
	err         error
}

func (s *staticTokens) Token(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return "", s.err
	}
	return s.tokens[min(s.invalidated, len(s.tokens)-1)], nil
}
func (s *staticTokens) Invalidate() { s.mu.Lock(); s.invalidated++; s.mu.Unlock() }

type fcmFake struct {
	mu      sync.Mutex
	reqs    []*http.Request
	bodies  []string
	respond func(n int, w http.ResponseWriter, r *http.Request)
}

func (f *fcmFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.reqs = append(f.reqs, r)
	f.bodies = append(f.bodies, string(b))
	n := len(f.reqs)
	f.mu.Unlock()
	if f.respond != nil {
		f.respond(n, w, r)
		return
	}
	_, _ = w.Write([]byte(`{"name":"projects/vettid-staging/messages/0:1"}`))
}

func fcmErr(status int, rpc, code string) func(int, http.ResponseWriter, *http.Request) {
	return func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		details := ""
		if code != "" {
			details = fmt.Sprintf(`,"details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":%q}]`, code)
		}
		fmt.Fprintf(w, `{"error":{"code":%d,"message":"The registration token SECRET-TOKEN is bad","status":%q%s}}`, status, rpc, details)
	}
}

// §6: the FCM request. A data message only, the constant collapse key,
// HIGH priority and a day's TTL; byte-identical for every wake apart
// from the token.
func TestFCMPayload(t *testing.T) {
	fake := &fcmFake{}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c := &FCMClient{Project: "vettid-staging", Tokens: &staticTokens{tokens: []string{"ya29.access"}}, BaseURL: srv.URL}
	for _, tok := range []string{"dT1:APA91b-x_y", "dT1:APA91b-x_y", "other<&>\"token"} {
		if r := c.Send(context.Background(), Message{Platform: FCM, AppID: "com.vettid.app", Token: tok}); r.Outcome != Sent {
			t.Fatalf("send: %+v", r)
		}
	}
	const want = `{"message":{"token":"dT1:APA91b-x_y","data":{"w":"1"},"android":{"priority":"HIGH","collapse_key":"w","ttl":"86400s"}}}`
	if fake.bodies[0] != want {
		t.Fatalf("payload\n got %s\nwant %s", fake.bodies[0], want)
	}
	if fake.bodies[1] != fake.bodies[0] {
		t.Fatal("two wakes of one token differ")
	}
	var m map[string]map[string]any
	if err := json.Unmarshal([]byte(fake.bodies[2]), &m); err != nil || m["message"]["token"] != "other<&>\"token" {
		t.Fatalf("token with JSON-significant characters: %s", fake.bodies[2])
	}
	if strings.Replace(fake.bodies[2], `other<&>\"token`, "dT1:APA91b-x_y", 1) != want {
		t.Fatalf("payload differs beyond the token: %s", fake.bodies[2])
	}
	if _, has := m["message"]["notification"]; has || len(m["message"]) != 3 {
		t.Fatalf("message members: %v", m["message"])
	}
	r := fake.reqs[0]
	if r.Method != "POST" || r.URL.Path != "/v1/projects/vettid-staging/messages:send" {
		t.Fatalf("%s %s", r.Method, r.URL.Path)
	}
	if r.Header.Get("Authorization") != "Bearer ya29.access" || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("headers %v", r.Header)
	}
	if DefaultFCMBaseURL != "https://fcm.googleapis.com" || SendTimeout != 5*time.Second {
		t.Fatal("endpoint or timeout constant changed")
	}
}

// §7: FCM's answers.
func TestFCMOutcomes(t *testing.T) {
	cases := []struct {
		name    string
		respond func(int, http.ResponseWriter, *http.Request)
		want    Outcome
		detail  string
		retry   int
	}{
		{"UNREGISTERED", fcmErr(404, "NOT_FOUND", "UNREGISTERED"), TokenGone, "UNREGISTERED", 0},
		{"bare 404", fcmErr(404, "NOT_FOUND", ""), TokenGone, "NOT_FOUND", 0},
		{"INVALID_ARGUMENT", fcmErr(400, "INVALID_ARGUMENT", "INVALID_ARGUMENT"), TokenInvalid, "INVALID_ARGUMENT", 0},
		{"bare 400", fcmErr(400, "INVALID_ARGUMENT", ""), TokenInvalid, "INVALID_ARGUMENT", 0},
		{"SENDER_ID_MISMATCH", fcmErr(403, "PERMISSION_DENIED", "SENDER_ID_MISMATCH"), TokenInvalid, "SENDER_ID_MISMATCH", 0},
		{"403", fcmErr(403, "PERMISSION_DENIED", ""), AuthFailed, "PERMISSION_DENIED", 0},
		{"THIRD_PARTY_AUTH_ERROR", fcmErr(401, "UNAUTHENTICATED", "THIRD_PARTY_AUTH_ERROR"), AuthFailed, "UNAUTHENTICATED", 0},
		{"QUOTA_EXCEEDED", func(_ int, w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "120")
			fcmErr(429, "RESOURCE_EXHAUSTED", "QUOTA_EXCEEDED")(0, w, r)
		}, RateLimited, "QUOTA_EXCEEDED", 120},
		{"429 without a wait", fcmErr(429, "RESOURCE_EXHAUSTED", ""), RateLimited, "RESOURCE_EXHAUSTED", 0},
		{"UNAVAILABLE", func(_ int, w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "99999")
			fcmErr(503, "UNAVAILABLE", "UNAVAILABLE")(0, w, r)
		}, Unavailable, "UNAVAILABLE", MaxRetryAfter},
		{"INTERNAL", fcmErr(500, "INTERNAL", "INTERNAL"), Unavailable, "INTERNAL", 0},
		{"502 HTML", func(_ int, w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(502)
			_, _ = w.Write([]byte("<html>bad gateway</html>"))
		}, Unavailable, "other", 0},
		{"unknown code", fcmErr(409, "ABORTED", "SOMETHING_NEW SECRET-TOKEN"), Rejected, "other", 0},
	}
	for _, c := range cases {
		fake := &fcmFake{respond: c.respond}
		srv := httptest.NewServer(fake)
		cl := &FCMClient{Project: "p", Tokens: &staticTokens{tokens: []string{"a"}}, BaseURL: srv.URL, Now: func() time.Time { return t0 }}
		r := cl.Send(context.Background(), Message{Platform: FCM, Token: "SECRET-TOKEN"})
		srv.Close()
		if r.Outcome != c.want || r.Detail != c.detail || r.RetryAfter != c.retry {
			t.Errorf("%s: %+v, want %v %q retry %d", c.name, r, c.want, c.detail, c.retry)
		}
		if strings.Contains(r.Detail, "SECRET") {
			t.Errorf("%s: the detail repeats the platform's text", c.name)
		}
	}
}

// A refused access token is dropped and fetched again, once.
func TestFCMUnauthenticatedRetry(t *testing.T) {
	fake := &fcmFake{respond: func(n int, w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer old" {
			fcmErr(401, "UNAUTHENTICATED", "")(n, w, r)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	ts := &staticTokens{tokens: []string{"old", "new"}}
	c := &FCMClient{Project: "p", Tokens: ts, BaseURL: srv.URL}
	if r := c.Send(context.Background(), Message{Token: "t"}); r.Outcome != Sent || ts.invalidated != 1 || len(fake.reqs) != 2 {
		t.Fatalf("%+v invalidated %d requests %d", r, ts.invalidated, len(fake.reqs))
	}
	// Still refused: an auth failure, after exactly one retry.
	ts2 := &staticTokens{tokens: []string{"old"}}
	c2 := &FCMClient{Project: "p", Tokens: ts2, BaseURL: srv.URL}
	if r := c2.Send(context.Background(), Message{Token: "t"}); r.Outcome != AuthFailed || ts2.invalidated != 1 || len(fake.reqs) != 4 {
		t.Fatalf("%+v invalidated %d requests %d", r, ts2.invalidated, len(fake.reqs))
	}
	// No access token at all.
	c3 := &FCMClient{Project: "p", Tokens: &staticTokens{err: errToken}, BaseURL: srv.URL}
	if r := c3.Send(context.Background(), Message{Token: "t"}); r.Outcome != AuthFailed || r.Detail != "access_token" {
		t.Fatalf("%+v", r)
	}
}

// §5.2 step 5, §7: a platform that does not answer in time, or cannot be
// reached, is provider_unavailable.
func TestFCMTimeoutAndTransport(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	c := &FCMClient{Project: "p", Tokens: &staticTokens{tokens: []string{"a"}}, BaseURL: srv.URL}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if r := c.Send(ctx, Message{Token: "t"}); r.Outcome != Unavailable || r.Detail != "timeout" {
		t.Fatalf("%+v", r)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("the send outlived its deadline")
	}
	dead := &FCMClient{Project: "p", Tokens: &staticTokens{tokens: []string{"a"}}, BaseURL: "http://127.0.0.1:1"}
	if r := dead.Send(context.Background(), Message{Token: "t"}); r.Outcome != Unavailable || r.Detail != "transport" {
		t.Fatalf("%+v", r)
	}
}

func TestRetryAfterHeader(t *testing.T) {
	for v, want := range map[string]int{"": 0, "7": 7, "-1": 0, "4000": 3600, "x": 0,
		t0.Add(90 * time.Second).UTC().Format(http.TimeFormat): 90, t0.Add(-time.Hour).UTC().Format(http.TimeFormat): 0} {
		h := http.Header{}
		if v != "" {
			h.Set("Retry-After", v)
		}
		if got := retryAfter(h, t0); got != want {
			t.Errorf("Retry-After %q: %d, want %d", v, got, want)
		}
	}
}
