// Package api is the push gateway's HTTP surface (PUSH-GATEWAY §5):
// POST /v1/register, POST /v1/confirm, POST /v1/wake and GET /v1/health.
//
// The gateway stores nothing about a registration: what it needs is
// sealed into the wake blob it returns, and a wake's opened record lives
// only as long as its request. This package writes no per-request log
// line; it logs errors of the service itself, throttled, and never a
// token, a blob, a wake key, an attestation document or a source address
// (§10.5).
package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-vault/vms/pushwire"

	"github.com/vettid/vettid-push/internal/attest"
	"github.com/vettid/vettid-push/internal/blob"
	"github.com/vettid/vettid-push/internal/metrics"
	"github.com/vettid/vettid-push/internal/provider"
	"github.com/vettid/vettid-push/internal/ratelimit"
)

// PathConfirm is the second step of a registration (§5.1): the vault
// returns the challenge code its app received by push.
const PathConfirm = "/v1/confirm"

// BlobMaxAge is the longest a wake blob is honoured after it was issued
// (§4): an older blob is answered blob_invalid, and the vault registers
// again, which verifies the token again. A reseal keeps the issue time.
const BlobMaxAge = 90 * 24 * time.Hour

// MaxBody bounds a request body: a registration is a 4 KiB token and
// little else, a wake a 6 KiB blob (the vault's supervisor sends at most
// this much).
const MaxBody = 16 << 10

// Limits are the gateway's abuse bounds (§8, §5.2 step 4). They live in
// each process's memory.
type Limits struct {
	// RegisterPerMinute and WakePerMinute bound one source address.
	RegisterPerMinute int
	WakePerMinute     int
	// TokenPerHour and TokenBurst bound the wakes of one push token.
	TokenPerHour int
	TokenBurst   int
	// ChallengePerHour and ChallengeBurst bound the registration
	// challenges sent to one push token, apart from its wakes.
	ChallengePerHour int
	ChallengeBurst   int
	// Coalesce is the window in which a second wake for a token is
	// answered without a second send (0: never).
	Coalesce time.Duration
	// ReplayCacheMax bounds the replay cache.
	ReplayCacheMax int
}

// DefaultLimits are the limits of §8.
func DefaultLimits() Limits {
	return Limits{RegisterPerMinute: 30, WakePerMinute: 6000, TokenPerHour: 60, TokenBurst: 10,
		ChallengePerHour: 10, ChallengeBurst: 5, Coalesce: 2 * time.Second, ReplayCacheMax: 200_000}
}

// Config configures a Server.
type Config struct {
	// Channel is prod, staging or dev: sealed into every blob's
	// associated data by Keys.
	Channel string
	// Keys seal and open wake blobs.
	Keys *blob.Keyring
	// Attest verifies registrations.
	Attest *attest.Verifier
	// Providers are the enabled platforms; a platform without a
	// provider is answered platform_invalid.
	Providers map[string]provider.Provider
	// AppIDs are the accepted app ids per platform (§5.1 step 3). A nil
	// map accepts every well-formed id (the dev stand-in only).
	AppIDs map[string][]string
	// AllowSandbox admits the APNs sandbox environment (staging and
	// dev, §10.4).
	AllowSandbox bool
	// TrustProxy takes the source address from the last
	// X-Forwarded-For hop: the one the load balancer appends.
	TrustProxy bool
	Limits     Limits
	Metrics    *metrics.Registry
	Log        *slog.Logger
	Now        func() time.Time
	// Dev, if set, is the stand-in's recorder and control state (-dev).
	Dev *Dev
}

// Server is the gateway's http.Handler.
type Server struct {
	cfg     Config
	now     func() time.Time
	log     *slog.Logger
	m       *metrics.Registry
	replay  *relayauth.ReplayCache
	perKey  *keyRecords
	regAddr *ratelimit.Limiter
	conAddr *ratelimit.Limiter
	wakAddr *ratelimit.Limiter
	token   *ratelimit.Limiter
	chal    *ratelimit.Limiter
	coal    *ratelimit.Coalescer
	macKey  [32]byte

	logMu   sync.Mutex
	logLast map[string]time.Time
	logSkip map[string]int
}

// New returns a server.
func New(cfg Config) (*Server, error) {
	if cfg.Keys == nil || cfg.Attest == nil {
		return nil, errors.New("api: blob keys and an attestation verifier are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.Metrics == nil {
		cfg.Metrics = metrics.New("vettid-push", cfg.Now)
	}
	l := cfg.Limits
	if l.RegisterPerMinute <= 0 || l.WakePerMinute <= 0 || l.TokenPerHour <= 0 || l.TokenBurst <= 0 || l.ReplayCacheMax <= 0 ||
		l.ChallengePerHour <= 0 || l.ChallengeBurst <= 0 {
		return nil, errors.New("api: limits must be positive")
	}
	s := &Server{cfg: cfg, now: cfg.Now, log: cfg.Log, m: cfg.Metrics,
		replay:  relayauth.NewReplayCache(l.ReplayCacheMax),
		perKey:  newKeyRecords(replayPerKey(l)),
		regAddr: ratelimit.New(float64(l.RegisterPerMinute)/60, l.RegisterPerMinute, 0),
		conAddr: ratelimit.New(float64(l.RegisterPerMinute)/60, l.RegisterPerMinute, 0),
		wakAddr: ratelimit.New(float64(l.WakePerMinute)/60, l.WakePerMinute, 0),
		token:   ratelimit.New(float64(l.TokenPerHour)/3600, l.TokenBurst, 1_000_000),
		chal:    ratelimit.New(float64(l.ChallengePerHour)/3600, l.ChallengeBurst, 1_000_000),
		coal:    ratelimit.NewCoalescer(l.Coalesce, 1_000_000),
		logLast: map[string]time.Time{}, logSkip: map[string]int{}}
	if _, err := rand.Read(s.macKey[:]); err != nil {
		return nil, err
	}
	return s, nil
}

// Sweep drops expired replay entries and idle limiter state; run it
// periodically.
func (s *Server) Sweep() {
	now := s.now()
	s.replay.Sweep(now)
	s.perKey.sweep(now)
	s.regAddr.Prune(now)
	s.conAddr.Prune(now)
	s.wakAddr.Prune(now)
	s.token.Prune(now)
	s.chal.Prune(now)
	s.coal.Prune(now)
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if p := recover(); p != nil {
			if p == http.ErrAbortHandler {
				panic(p)
			}
			// The panic's type only: its value could hold request data.
			s.logError("panic", "panic in handler", "type", fmt.Sprintf("%T", p))
			s.answerError(w, fail(CodeInternal))
		}
	}()
	switch {
	case r.URL.Path == pushwire.PathHealth && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, struct{}{})
	case r.URL.Path == pushwire.PathRegister && r.Method == http.MethodPost:
		s.register(w, r)
	case r.URL.Path == PathConfirm && r.Method == http.MethodPost:
		s.confirm(w, r)
	case r.URL.Path == pushwire.PathWake && r.Method == http.MethodPost:
		s.wake(w, r)
	default:
		writeError(w, fail(CodeNotFound))
	}
}

// answerError writes an error answer; every `internal` is counted (it
// raises an alarm, §10.5).
func (s *Server) answerError(w http.ResponseWriter, e *apiError) {
	if e.code == CodeInternal {
		s.m.Count("internal_errors")
	}
	writeError(w, e)
}

// logError logs an error of the service at most once a minute per kind,
// with the number of occurrences left out since. Attributes are from
// closed sets; no request data reaches the log.
func (s *Server) logError(kind, msg string, attrs ...any) {
	now := s.now()
	s.logMu.Lock()
	if last, ok := s.logLast[kind]; ok && now.Sub(last) < time.Minute && now.Sub(last) >= 0 {
		s.logSkip[kind]++
		s.logMu.Unlock()
		return
	}
	skipped := s.logSkip[kind]
	s.logLast[kind], s.logSkip[kind] = now, 0
	s.logMu.Unlock()
	s.log.Error(msg, append(attrs, "suppressed_since_last", skipped)...)
}

// clientAddr returns the source address. With TrustProxy the LAST
// X-Forwarded-For entry is used: the hop the load balancer appended.
// Earlier entries are client-controlled and ignored.
func (s *Server) clientAddr(r *http.Request) netip.Addr {
	if s.cfg.TrustProxy {
		if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
			last := xff[len(xff)-1]
			if i := strings.LastIndexByte(last, ','); i >= 0 {
				last = last[i+1:]
			}
			if a, err := netip.ParseAddr(strings.TrimSpace(last)); err == nil {
				return a.Unmap()
			}
		}
	}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// addrKey is the per-address limiter key: the IPv4 address or the IPv6
// /64. It stays in the limiter's memory and is never logged.
func addrKey(a netip.Addr) string {
	if !a.IsValid() {
		return "unknown"
	}
	if a.Is4() {
		return a.String()
	}
	p, _ := a.Prefix(64)
	return p.String()
}

// tokenKey is the per-token limiter key: an HMAC of the token under a
// per-process random key (§8).
func (s *Server) tokenKey(rec blob.Record) string {
	h := hmac.New(sha256.New, s.macKey[:])
	h.Write([]byte(rec.Platform))
	h.Write([]byte{0})
	h.Write([]byte(rec.Environment))
	h.Write([]byte{0})
	h.Write([]byte(rec.Token))
	return string(h.Sum(nil))
}

// verify reads the body and checks the signature and the freshness
// window (Relay Protocol §4.1). It records nothing: a signature proves
// only that the sender holds some Ed25519 key, and keys are free, so a
// request enters the replay cache (recordReplay) only once the handler
// has established that the key is one the gateway knows: on a wake, the
// key sealed in a blob of its own; on a registration, the key a vault
// release attested for this very request; on a confirmation, the key
// sealed in a pending registration of its own.
//
// It returns the reading of the clock it judged freshness by, and
// recordReplay must be given the same one. A record expires one second
// after its timestamp stops being fresh; with a second, later reading a
// replay at the edge of the window would pass freshness here and then
// find its own record expired.
//
// What a handler does between verify and recordReplay does not depend
// on whether the request was seen before and changes nothing a later
// request is judged by: it reads the request and the configuration.
// (It does count a refused registration in attestation_failures, each
// time the request is sent.)
func (s *Server) verify(r *http.Request) (relayauth.SignedRequest, []byte, time.Time, *apiError) {
	now := s.now()
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, MaxBody))
	if err != nil {
		return relayauth.SignedRequest{}, nil, now, fail(CodeBadRequest)
	}
	sr, err := relayauth.ParseHeaders(r.Header)
	if err != nil {
		return sr, nil, now, fail(CodeSignatureInvalid)
	}
	if err := sr.Verify(http.MethodPost, r.URL.Path, relayauth.BodyHash(body), now); err != nil {
		if errors.Is(err, relayauth.ErrTimestampStale) {
			return sr, nil, now, fail(CodeTimestampStale)
		}
		return sr, nil, now, fail(CodeSignatureInvalid)
	}
	return sr, body, now, nil
}

// recordReplay refuses a request seen before and records one that was
// not. now is verify's reading of the clock.
//
// That of any number of identical requests, concurrent or not, exactly
// one gets nil rests on relayauth.ReplayCache.Check, which looks up and
// records in one step under its lock; no test can show the absence of a
// gap there, so do not split it into a lookup and a later record. The
// cache lives in this process: with several tasks a request can be
// accepted once by each (§8), as the limits count per task.
//
// A handler calls it after its authenticating checks and before
// anything a replay must not repeat (the per-token limit, the
// coalescer, a platform send, a seal).
//
// Two refusals shed load, both 429 rate_limited and both failing
// closed, never admitting a request unrecorded: the key already has its
// cap of live records (only this key's requests are refused, until one
// of its records expires), or the cache is full.
func (s *Server) recordReplay(sr relayauth.SignedRequest, now time.Time) *apiError {
	exp := sr.Time.Add(relayauth.FreshnessWindow + time.Second) // as ReplayCache.Check keeps it
	ok, wait, err := s.perKey.record(sr.Key, exp, now, func() error { return s.replay.Check(sr, now) })
	switch {
	case !ok:
		s.m.Count("rate_limited", metrics.Dim{Name: "scope", Value: "key"})
		return failAfter(CodeRateLimited, ratelimit.RetryAfterSeconds(wait))
	case err == nil:
		return nil
	case errors.Is(err, relayauth.ErrReplayCacheFull):
		s.m.Count("rate_limited", metrics.Dim{Name: "scope", Value: "replay_cache"})
		return failAfter(CodeRateLimited, 1)
	default:
		return fail(CodeReplayDetected)
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// appAllowed reports whether app is in the channel's list for platform.
func (s *Server) appAllowed(platform, app string) bool {
	return s.cfg.AppIDs == nil || contains(s.cfg.AppIDs[platform], app)
}

// sendContext is the context of a platform send: it does not end when
// the caller hangs up, so a send in flight completes and coalescing
// stays truthful; the provider bounds it (provider.SendTimeout).
func sendContext(r *http.Request) context.Context { return context.WithoutCancel(r.Context()) }
