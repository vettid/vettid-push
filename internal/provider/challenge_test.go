package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

const testCode = "q3Zl0-Yc_w7Tj2b1d9KfAA"

// §5.1, §6: a registration's token challenge through FCM is a data
// message whose only member is the code, high priority, under its own
// collapse key, kept by Google no longer than the challenge is valid.
// Its answers map as a wake's do.
func TestFCMChallenge(t *testing.T) {
	fake := &fcmFake{}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c := &FCMClient{Project: "vettid-staging", Tokens: &staticTokens{tokens: []string{"ya29.access"}}, BaseURL: srv.URL}
	m := Message{Platform: FCM, AppID: "com.vettid.app", Token: "dT1:APA91b-x_y", Challenge: testCode}
	if r := c.Send(context.Background(), m); r.Outcome != Sent {
		t.Fatalf("send: %+v", r)
	}
	const want = `{"message":{"token":"dT1:APA91b-x_y","data":{"c":"` + testCode + `"},"android":{"priority":"HIGH","collapse_key":"c","ttl":"600s"}}}`
	if fake.bodies[0] != want {
		t.Fatalf("payload\n got %s\nwant %s", fake.bodies[0], want)
	}
	fake.respond = fcmErr(404, "NOT_FOUND", "UNREGISTERED")
	if r := c.Send(context.Background(), m); r.Outcome != TokenGone {
		t.Fatalf("unregistered: %+v", r)
	}
	// Nothing but a code the gateway could have made enters a payload.
	n := len(fake.bodies)
	for _, bad := range []string{`x"}`, "a b", string(make([]byte, 65))} {
		m.Challenge = bad
		if r := c.Send(context.Background(), m); r.Outcome != Rejected {
			t.Fatalf("code %q: %+v", bad, r)
		}
	}
	if len(fake.bodies) != n {
		t.Fatal("a malformed code was sent")
	}
}

// §5.1, §6: through APNs the challenge is a background push (priority 5,
// as Apple requires for it): nothing is shown, the code is the only
// variable part, and Apple keeps it no longer than the challenge is
// valid.
func TestAPNsChallenge(t *testing.T) {
	secret, _ := apnsSecretFor(t)
	fake := &apnsFake{}
	srv := h2Server(fake)
	defer srv.Close()
	c := apnsClient(t, secret, srv, nil, func() time.Time { return t0 })
	m := Message{Platform: APNs, Environment: EnvProduction, AppID: "com.vettid.app", Token: apnsToken, Challenge: testCode}
	if r := c.Send(context.Background(), m); r.Outcome != Sent {
		t.Fatalf("send: %+v", r)
	}
	r := fake.reqs[0]
	if want := `{"aps":{"content-available":1},"c":"` + testCode + `"}`; r.body != want {
		t.Fatalf("payload\n got %s\nwant %s", r.body, want)
	}
	for k, v := range map[string]string{"apns-push-type": "background", "apns-priority": "5", "apns-topic": "com.vettid.app",
		"apns-expiration": strconv.FormatInt(t0.Unix()+600, 10)} {
		if r.header.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, r.header.Get(k), v)
		}
	}
	fake.respond = func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"reason":"BadDeviceToken"}`))
	}
	if r := c.Send(context.Background(), m); r.Outcome != TokenInvalid {
		t.Fatalf("bad token: %+v", r)
	}
	m.Challenge = `x"}`
	if r := c.Send(context.Background(), m); r.Outcome != Rejected || len(fake.reqs) != 2 {
		t.Fatalf("malformed code: %+v", r)
	}
	// A wake is still the fixed alert.
	fake.respond = nil
	m.Challenge = ""
	if r := c.Send(context.Background(), m); r.Outcome != Sent || fake.reqs[2].body != APNsPayload ||
		fake.reqs[2].header.Get("apns-push-type") != "alert" {
		t.Fatalf("wake after a challenge: %+v %s", r, fake.reqs[2].body)
	}
}
