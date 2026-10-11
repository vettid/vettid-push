package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/vettid/vettid-push/internal/provider"
)

// Dev is the gateway stand-in's state (`vettid-push -dev`, PUSH-GATEWAY
// §10.4): it records wakes instead of sending them to FCM or APNs, and
// its control routes let a test inject answers. It replaces the vault's
// internal/pushtest in the dev stack and serves the same control API.
//
// DEV ONLY: a recorded wake keeps the SHA-256 of its token, which a
// release gateway never keeps. A Dev exists only under -dev.
type Dev struct {
	now func() time.Time

	mu       sync.Mutex
	wakes    []DevWake
	regs     int
	failures []DevFailure
	reseal   int
	resealed []string
	refusals map[string]int
	changed  chan struct{}
}

// DevWake is one recorded wake: what the gateway would have sent.
type DevWake struct {
	At          time.Time `json:"at"`
	Platform    string    `json:"platform"`
	Environment string    `json:"environment,omitempty"`
	AppID       string    `json:"app_id"`
	TokenSHA256 string    `json:"token_sha256"`
	Class       string    `json:"class"`
}

// DevFailure is an injected answer for the next wake(s).
type DevFailure struct {
	Status     int    `json:"status"`
	Code       string `json:"code"`
	RetryAfter int    `json:"retry_after,omitempty"`
	// Count is how many wakes it answers (default 1).
	Count int `json:"count,omitempty"`
}

// NewDev returns an empty stand-in state.
func NewDev(now func() time.Time) *Dev {
	if now == nil {
		now = time.Now
	}
	return &Dev{now: now, refusals: map[string]int{}, changed: make(chan struct{})}
}

// bump wakes waiters; d.mu held.
func (d *Dev) bump() {
	close(d.changed)
	d.changed = make(chan struct{})
}

// Send implements provider.Provider: it records the wake, or answers
// with the next injected failure.
func (d *Dev) Send(_ context.Context, m provider.Message) provider.Result {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.failures) > 0 {
		f := &d.failures[0]
		o := &provider.Override{Status: f.Status, Code: f.Code, RetryAfter: f.RetryAfter}
		if f.Count--; f.Count <= 0 {
			d.failures = d.failures[1:]
		}
		return provider.Result{Outcome: provider.Rejected, Override: o}
	}
	th := sha256.Sum256([]byte(m.Token))
	d.wakes = append(d.wakes, DevWake{At: d.now().UTC(), Platform: m.Platform, Environment: m.Environment,
		AppID: m.AppID, TokenSHA256: hex.EncodeToString(th[:]), Class: "notify"})
	d.bump()
	return provider.Result{Outcome: provider.Sent}
}

// note counts a finished request: a registration, or a refusal by
// "op:code".
func (d *Dev) note(op string, e *apiError) {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case e != nil:
		d.refusals[op+":"+e.code]++
	case op == "register":
		d.regs++
	default:
		return
	}
	d.bump()
}

// takeReseal reports whether the wake being answered gets a forced
// reseal.
func (d *Dev) takeReseal() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.reseal <= 0 {
		return false
	}
	d.reseal--
	return true
}

func (d *Dev) noteReseal(b string) {
	d.mu.Lock()
	d.resealed = append(d.resealed, b)
	d.mu.Unlock()
}

// Wakes returns the recorded wakes.
func (d *Dev) Wakes() []DevWake {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]DevWake{}, d.wakes...)
}

// Registrations returns how many registrations succeeded.
func (d *Dev) Registrations() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.regs
}

// Refusals returns how many requests were refused, by "op:code".
func (d *Dev) Refusals() map[string]int {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := map[string]int{}
	for k, v := range d.refusals {
		out[k] = v
	}
	return out
}

// Resealed returns the blobs handed out as reseals.
func (d *Dev) Resealed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.resealed...)
}

// FailNext answers the next wakes with f instead of recording them.
func (d *Dev) FailNext(f DevFailure) {
	if f.Count <= 0 {
		f.Count = 1
	}
	d.mu.Lock()
	d.failures = append(d.failures, f)
	d.mu.Unlock()
}

// ResealNext answers the next n recorded wakes with a reseal.
func (d *Dev) ResealNext(n int) {
	d.mu.Lock()
	d.reseal += n
	d.mu.Unlock()
}

// Reset forgets the recorded wakes, counts and injected answers (the
// blob key stays, so registered vaults keep working).
func (d *Dev) Reset() {
	d.mu.Lock()
	d.wakes, d.regs, d.failures, d.reseal, d.resealed = nil, 0, nil, 0, nil
	d.refusals = map[string]int{}
	d.bump()
	d.mu.Unlock()
}

// Wait blocks until cond holds (checked at every change), the timeout or
// the end of ctx.
func (d *Dev) Wait(ctx context.Context, timeout time.Duration, cond func(*Dev) bool) bool {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		d.mu.Lock()
		ch := d.changed
		d.mu.Unlock()
		if cond(d) {
			return true
		}
		select {
		case <-ch:
		case <-deadline.C:
			return cond(d)
		case <-ctx.Done():
			return false
		}
	}
}

func validCode(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// ControlHandler serves the stand-in's control routes (the same as the
// vault dev stack's, cmd/devstack/push.go). Bind it to loopback or a
// test network only; it is not part of the gateway's API.
//
//	GET  /dev/push        {registrations, wakes: [{at, platform, environment?, app_id,
//	                      token_sha256, class}], refusals: {"op:code": n}}
//	POST /dev/push/fail   {status, code, retry_after?, count?}: the next count wakes
//	                      (default 1) are answered with that error instead of recorded
//	POST /dev/push/reseal {count?}: the next count wakes answer with a reseal
//	POST /dev/push/reset  forgets wakes, counts and injected answers
//	POST /dev/push/wait   {wakes: N, timeout_s}: waits (default 30 s, at most 300) until
//	                      N wakes are recorded; 404 {"error": "timeout"} otherwise
func (d *Dev) ControlHandler() http.Handler {
	state := func() map[string]any {
		return map[string]any{"registrations": d.Registrations(), "wakes": d.Wakes(), "refusals": d.Refusals()}
	}
	bad := func(w http.ResponseWriter) { writeJSON(w, 400, map[string]any{"error": "bad_request"}) }
	mux := http.NewServeMux()
	mux.HandleFunc("GET /dev/push", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, state()) })
	mux.HandleFunc("POST /dev/push/fail", func(w http.ResponseWriter, r *http.Request) {
		var f DevFailure
		if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&f) != nil || f.Status < 400 || f.Status > 599 || !validCode(f.Code) ||
			f.Count < 0 || f.Count > 1000 || f.RetryAfter < 0 || f.RetryAfter > 3600 {
			bad(w)
			return
		}
		d.FailNext(f)
		writeJSON(w, 200, map[string]any{})
	})
	mux.HandleFunc("POST /dev/push/reseal", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Count int `json:"count"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in)
		if in.Count <= 0 || in.Count > 1000 {
			in.Count = 1
		}
		d.ResealNext(in.Count)
		writeJSON(w, 200, map[string]any{})
	})
	mux.HandleFunc("POST /dev/push/reset", func(w http.ResponseWriter, r *http.Request) {
		d.Reset()
		writeJSON(w, 200, map[string]any{})
	})
	mux.HandleFunc("POST /dev/push/wait", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Wakes    int `json:"wakes"`
			TimeoutS int `json:"timeout_s"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in) != nil || in.Wakes < 1 {
			bad(w)
			return
		}
		if in.TimeoutS <= 0 || in.TimeoutS > 300 {
			in.TimeoutS = 30
		}
		if !d.Wait(r.Context(), time.Duration(in.TimeoutS)*time.Second, func(d *Dev) bool { return len(d.Wakes()) >= in.Wakes }) {
			writeJSON(w, 404, map[string]any{"error": "timeout"})
			return
		}
		writeJSON(w, 200, state())
	})
	return mux
}
