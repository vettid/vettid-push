package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/pushwire"

	"github.com/vettid/vettid-push/internal/provider"
)

// §10.4: the stand-in records wakes instead of sending them and serves
// the control routes the vault's dev stack uses (cmd/devstack/push.go),
// with the same JSON.
func TestDevStandIn(t *testing.T) {
	var dev *Dev
	g := newGW(t, func(g *gw) {
		dev = NewDev(g.clk.now)
		g.cfg.Channel, g.cfg.Dev, g.cfg.AppIDs = "dev", dev, nil
		g.cfg.Providers = map[string]provider.Provider{provider.FCM: dev, provider.APNs: dev}
	})
	ctl := httptest.NewServer(dev.ControlHandler())
	defer ctl.Close()
	call := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, ctl.URL+path, bytes.NewReader([]byte(body)))
		resp, err := ctl.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return resp.StatusCode, m
	}
	ctx := context.Background()

	// Any well-formed app id registers; wakes are recorded.
	reg := pushwire.Registration{Platform: "apns", Token: apnsReg.Token, AppID: "org.example.anything", Environment: "sandbox"}
	key, wb := g.register(reg)
	if _, err := g.vault().Wake(ctx, key, wb); err != nil {
		t.Fatal(err)
	}
	st, state := call("GET", "/dev/push", "")
	if st != 200 || state["registrations"] != float64(1) {
		t.Fatalf("state: %d %v", st, state)
	}
	// The registration's challenge is recorded with its code, for the
	// dev stack to hand to its vault as the app would.
	if ch := state["challenges"].([]any); len(ch) != 1 || ch[0].(map[string]any)["code"] != g.code(reg) ||
		ch[0].(map[string]any)["app_id"] != "org.example.anything" {
		t.Fatalf("challenges: %v", state["challenges"])
	}
	wakes := state["wakes"].([]any)
	th := sha256.Sum256([]byte(reg.Token))
	w := wakes[0].(map[string]any)
	if len(wakes) != 1 || w["platform"] != "apns" || w["environment"] != "sandbox" || w["app_id"] != "org.example.anything" ||
		w["class"] != "notify" || w["token_sha256"] != hex.EncodeToString(th[:]) || w["at"] != t0.Format(time.RFC3339) {
		t.Fatalf("recorded wake %v", w)
	}

	// Injected failures answer the next wakes, in order.
	if st, _ := call("POST", "/dev/push/fail", `{"status":410,"code":"token_gone"}`); st != 200 {
		t.Fatal(st)
	}
	if st, _ := call("POST", "/dev/push/fail", `{"status":429,"code":"rate_limited","retry_after":7,"count":2}`); st != 200 {
		t.Fatal(st)
	}
	for i, want := range []struct {
		status, retry int
		code          string
	}{{410, 0, "token_gone"}, {429, 7, "rate_limited"}, {429, 7, "rate_limited"}} {
		g.clk.add(3 * time.Second)
		_, err := g.vault().Wake(ctx, key, wb)
		if ge := gwErr(err); ge == nil || ge.Status != want.status || ge.Code != want.code || ge.RetryAfter != want.retry {
			t.Fatalf("injected answer %d: %v", i, err)
		}
	}
	for _, bad := range []string{`{"status":200,"code":"ok"}`, `{"status":500,"code":"Not A Code"}`, `{"status":500,"code":"x","retry_after":99999}`, `nope`} {
		if st, _ := call("POST", "/dev/push/fail", bad); st != 400 {
			t.Errorf("fail %s: %d", bad, st)
		}
	}

	// A forced reseal.
	if st, _ := call("POST", "/dev/push/reseal", `{}`); st != 200 {
		t.Fatal(st)
	}
	g.clk.add(3 * time.Second)
	reseal, err := g.vault().Wake(ctx, key, wb)
	if err != nil || reseal == "" || len(dev.Resealed()) != 1 || dev.Resealed()[0] != reseal {
		t.Fatalf("forced reseal: %q %v", reseal, err)
	}
	g.clk.add(3 * time.Second)
	if r, err := g.vault().Wake(ctx, key, reseal); err != nil || r != "" {
		t.Fatalf("wake with the reseal: %q %v", r, err)
	}

	// Refusals are counted by "op:code".
	g.clk.add(3 * time.Second)
	_, _ = g.vault().Wake(ctx, newKey(t), wb)
	_, state = call("GET", "/dev/push", "")
	ref := state["refusals"].(map[string]any)
	if ref["wake:blob_invalid"] != float64(1) || ref["wake:token_gone"] != float64(1) || ref["wake:rate_limited"] != float64(2) {
		t.Fatalf("refusals %v", ref)
	}
	if len(state["wakes"].([]any)) != 3 {
		t.Fatalf("%d wakes recorded", len(state["wakes"].([]any)))
	}

	// wait: returns once N wakes are recorded, or 404 at the timeout.
	done := make(chan int, 1)
	go func() { st, _ := call("POST", "/dev/push/wait", `{"wakes":4,"timeout_s":20}`); done <- st }()
	g.clk.add(3 * time.Second)
	if _, err := g.vault().Wake(ctx, key, reseal); err != nil {
		t.Fatal(err)
	}
	select {
	case st := <-done:
		if st != 200 {
			t.Fatalf("wait: %d", st)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("wait did not return after the fourth wake")
	}
	if !dev.Wait(ctx, time.Millisecond, func(d *Dev) bool { return len(d.Wakes()) >= 4 }) ||
		dev.Wait(ctx, 5*time.Millisecond, func(d *Dev) bool { return len(d.Wakes()) >= 5 }) {
		t.Fatal("Wait")
	}
	if st, _ := call("POST", "/dev/push/wait", `{"wakes":0}`); st != 400 {
		t.Fatalf("wait without a count: %d", st)
	}

	// reset forgets everything but the blob key.
	if st, _ := call("POST", "/dev/push/reset", ``); st != 200 {
		t.Fatal(st)
	}
	_, state = call("GET", "/dev/push", "")
	if state["registrations"] != float64(0) || len(state["wakes"].([]any)) != 0 || len(state["refusals"].(map[string]any)) != 0 ||
		len(state["challenges"].([]any)) != 0 {
		t.Fatalf("after reset: %v", state)
	}
	g.clk.add(3 * time.Second)
	if _, err := g.vault().Wake(ctx, key, reseal); err != nil {
		t.Fatalf("a blob from before the reset: %v", err)
	}
	// The control routes are not on the gateway's own listener.
	if a := g.do(rawReq{path: "/dev/push", method: "GET"}); a.status != 404 {
		t.Fatalf("control route on the public handler: %d", a.status)
	}
}
