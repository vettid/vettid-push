package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-vault/vms/pushwire"

	"github.com/vettid/vettid-push/internal/nsmtest"
	"github.com/vettid/vettid-push/internal/provider"
)

// PUSH-GATEWAY §10.5: the log holds errors and starts only; never a
// token, a blob, a wake key, an attestation document, a source address
// or a per-request line. Metrics have no dimension that identifies a
// token, key, vault or address.
//
// The test drives every kind of request, successful and refused, from a
// known address with known secrets, captures everything the gateway
// writes (log and metric lines) and searches it.
func TestLogAndMetricsCarryNoRequestData(t *testing.T) {
	const addr = "203.0.113.77"
	g := newGW(t, func(g *gw) { g.cfg.TrustProxy = true })

	// Requests are built by hand so that every header value is known.
	var secrets []string
	note := func(s ...string) { secrets = append(secrets, s...) }
	note(addr, fcmReg.Token, apnsReg.Token)

	register := func(reg pushwire.Registration) (ed25519.PrivateKey, string) {
		key := newKey(t)
		body := reg.Body()
		at := g.clk.now()
		d := relayauth.Digest("POST", pushwire.PathRegister, at.UTC().Format(time.RFC3339Nano), relayauth.BodyHash(body))
		doc, _ := g.nsm.Attest(d[:], nil, key.Public().(ed25519.PublicKey))
		hdr := nsmtest.Header(doc)
		a := g.do(rawReq{path: pushwire.PathRegister, body: body, key: key, at: at, attest: &hdr, xff: addr})
		if a.status != 201 {
			t.Fatalf("register: %d %s", a.status, a.body)
		}
		wb, _ := pushwire.ParseRegistered([]byte(a.body))
		note(wb, hdr, base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
			base64.StdEncoding.EncodeToString(key.Seed()), base64.StdEncoding.EncodeToString(doc[:60]))
		return key, wb
	}
	wake := func(key ed25519.PrivateKey, wb string) answer {
		g.clk.add(3 * time.Second)
		return g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(wb), key: key, xff: addr})
	}

	fk, fb := register(fcmReg)
	g.clk.add(3 * time.Second)
	ak, ab := register(apnsReg)

	// 1. Successful traffic writes nothing at all.
	for i := 0; i < 5; i++ {
		if a := wake(fk, fb); a.status != 202 {
			t.Fatalf("wake: %d %s", a.status, a.body)
		}
		if a := wake(ak, ab); a.status != 202 {
			t.Fatalf("wake: %d %s", a.status, a.body)
		}
	}
	g.do(rawReq{path: pushwire.PathHealth, method: "GET", xff: addr})
	if l := g.logs.String(); l != "" {
		t.Fatalf("successful requests wrote log lines (no per-request line is allowed):\n%s", l)
	}

	// 2. Refusals of every kind write nothing either: they are the
	// caller's errors, not the service's.
	g.clk.add(time.Minute)
	g.do(rawReq{path: pushwire.PathRegister, body: fcmReg.Body(), xff: addr})                                          // unsigned
	g.do(rawReq{path: pushwire.PathRegister, body: fcmReg.Body(), key: newKey(t), attest: str(""), xff: addr})         // unattested
	g.do(rawReq{path: pushwire.PathRegister, body: fcmReg.Body(), key: newKey(t), attest: str("Zm9yZ2Vk"), xff: addr}) // forged
	g.do(rawReq{path: pushwire.PathRegister, body: []byte(`{"platform":"fcm","token":"` + fcmReg.Token + `","app_id":"com.example.other"}`), key: newKey(t), xff: addr})
	wake(ak, fb)     // another signer
	wake(fk, "AAAA") // garbage blob
	g.fcm.set(provider.Result{Outcome: provider.TokenGone, Detail: "UNREGISTERED"})
	wake(fk, fb)
	g.fcm.set(provider.Result{Outcome: provider.RateLimited, RetryAfter: 30})
	wake(fk, fb)
	g.fcm.set(provider.Result{})
	for i := 0; i < 12; i++ { // into the per-token limit
		g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(ab), key: ak, xff: addr})
		g.clk.add(2100 * time.Millisecond)
	}
	if l := g.logs.String(); l != "" {
		t.Fatalf("refused requests wrote log lines:\n%s", l)
	}

	// 3. Errors of the service itself are logged, throttled to one line
	// a minute per kind: an outage does not turn into a per-request log.
	g.clk.add(2 * time.Hour)
	g.fcm.set(provider.Result{Outcome: provider.Unavailable, Detail: "UNAVAILABLE"})
	for i := 0; i < 10; i++ { // the token's burst: every one reaches the platform
		g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(fb), key: fk, xff: addr})
		g.clk.add(time.Second)
	}
	lines := logLines(g.logs.String())
	if len(lines) != 1 {
		t.Fatalf("%d log lines for 10 failed sends within a minute, want 1:\n%s", len(lines), g.logs.String())
	}
	g.clk.add(time.Minute)
	g.do(rawReq{path: pushwire.PathWake, body: pushwire.WakeBody(fb), key: fk, xff: addr})
	g.apns.set(provider.Result{Outcome: provider.AuthFailed, Detail: "InvalidProviderToken"})
	g.clk.add(time.Hour)
	wake(ak, ab)
	lines = logLines(g.logs.String())
	if len(lines) != 3 {
		t.Fatalf("%d log lines, want 3:\n%s", len(lines), g.logs.String())
	}
	allowed := map[string]bool{"time": true, "level": true, "msg": true, "platform": true, "outcome": true,
		"detail": true, "suppressed_since_last": true, "type": true}
	for i, l := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line is not JSON: %s", l)
		}
		if m["level"] != "ERROR" || m["msg"] != "platform send failed" {
			t.Errorf("line %d: %s", i, l)
		}
		for k := range m {
			if !allowed[k] {
				t.Errorf("log attribute %q is not in the allowed set: %s", k, l)
			}
		}
	}
	var second map[string]any
	_ = json.Unmarshal([]byte(lines[1]), &second)
	if second["suppressed_since_last"] != float64(9) || second["detail"] != "UNAVAILABLE" || second["platform"] != "fcm" {
		t.Errorf("throttled line: %s", lines[1])
	}
	if !strings.Contains(lines[2], `"outcome":"provider_auth"`) || !strings.Contains(lines[2], `"detail":"InvalidProviderToken"`) {
		t.Errorf("auth failure line (the §10.5 alarm reads it): %s", lines[2])
	}

	// 4. The metric lines.
	var mbuf bytes.Buffer
	if err := g.metrics.Flush(&mbuf); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{"registrations": true, "wakes": true, "provider_latency_ms": true,
		"attestation_failures": true, "rate_limited": true, "blob_resealed": true}
	dims := map[string]*regexp.Regexp{
		"platform":    regexp.MustCompile(`^(fcm|apns|unknown)$`),
		"environment": regexp.MustCompile(`^(production|sandbox|none)$`),
		"outcome":     regexp.MustCompile(`^[a-z_]{2,32}$`),
		"reason":      regexp.MustCompile(`^[a-z0-9_]{2,32}$`),
		"scope":       regexp.MustCompile(`^(token|address_register|address_wake|replay_cache)$`),
	}
	seen := map[string]bool{}
	for _, l := range logLines(mbuf.String()) {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("metric line is not JSON: %s", l)
		}
		cw := m["_aws"].(map[string]any)["CloudWatchMetrics"].([]any)[0].(map[string]any)
		name := cw["Metrics"].([]any)[0].(map[string]any)["Name"].(string)
		seen[name] = true
		if !names[name] {
			t.Errorf("metric %q is not one of §10.5's", name)
		}
		for k, v := range m {
			if k == "_aws" || k == name {
				continue
			}
			re, ok := dims[k]
			if !ok {
				t.Errorf("metric member %q in %s", k, l)
				continue
			}
			if s, _ := v.(string); !re.MatchString(s) {
				t.Errorf("dimension %s=%v is outside its closed set", k, v)
			}
		}
	}
	for _, n := range []string{"registrations", "wakes", "provider_latency_ms", "attestation_failures", "rate_limited"} {
		if !seen[n] {
			t.Errorf("metric %s was not written", n)
		}
	}
	if n := len(logLines(mbuf.String())); n > 40 {
		t.Errorf("%d metric lines: one per series, not per request", n)
	}

	// 5. Nothing the gateway wrote holds request data. Long values are
	// also searched for by their pieces.
	all := g.logs.String() + mbuf.String()
	for _, s := range secrets {
		probes := []string{s}
		if len(s) > 48 {
			probes = append(probes, s[:24], s[len(s)/2-12:len(s)/2+12], s[len(s)-24:])
		}
		for _, p := range probes {
			if strings.Contains(all, p) {
				t.Errorf("the output contains request data %q…", p[:min(len(p), 12)])
			}
		}
	}
	for _, s := range []string{"X-Forwarded-For", "remote", "wake_blob", fcmReg.AppID} {
		if strings.Contains(all, s) {
			t.Errorf("the output contains %q", s)
		}
	}
}
