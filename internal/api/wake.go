package api

import (
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/vettid/vettid-vault/vms/pushwire"

	"github.com/vettid/vettid-push/internal/blob"
	"github.com/vettid/vettid-push/internal/provider"
	"github.com/vettid/vettid-push/internal/ratelimit"
)

// envDim is the environment dimension: production or sandbox for apns,
// none for fcm.
func envDim(e string) string {
	if e == provider.EnvProduction || e == provider.EnvSandbox {
		return e
	}
	return "none"
}

// wake is POST /v1/wake (§5.2).
func (s *Server) wake(w http.ResponseWriter, r *http.Request) {
	platform, env, outcome := "unknown", "none", ""
	e := func() *apiError {
		if ok, wait := s.wakAddr.Allow(addrKey(s.clientAddr(r)), s.now()); !ok {
			s.m.Count("rate_limited", dim("scope", "address_wake"))
			return failAfter(CodeRateLimited, ratelimit.RetryAfterSeconds(wait))
		}
		// 1. Signature, freshness, replay cache.
		sr, body, e := s.auth(r)
		if e != nil {
			return e
		}
		wb, class, err := pushwire.ParseWake(body)
		if err != nil || class != pushwire.ClassNotify {
			return fail(CodeBadRequest)
		}
		// 2. Open the blob; its key must be the signer. Every failure
		// is the same blob_invalid (no oracle).
		rec, current, err := s.cfg.Keys.Open(wb)
		if err != nil || subtle.ConstantTimeCompare(rec.Key, sr.Key) != 1 {
			return fail(CodeBlobInvalid)
		}
		prov := s.cfg.Providers[rec.Platform]
		// A record this gateway would no longer seal (a platform or an
		// app id since removed from the channel) is not sent.
		if prov == nil || !s.appAllowed(rec.Platform, rec.AppID) ||
			rec.Environment == provider.EnvSandbox && !s.cfg.AllowSandbox ||
			(pushwire.Registration{Platform: rec.Platform, Token: rec.Token, AppID: rec.AppID, Environment: rec.Environment}).Validate() != nil {
			return fail(CodeBlobInvalid)
		}
		platform, env = platformDim(rec.Platform), envDim(rec.Environment)
		// 3. The per-token limit.
		tk := s.tokenKey(rec)
		if ok, wait := s.token.Allow(tk, s.now()); !ok {
			s.m.Count("rate_limited", dim("scope", "token"))
			return failAfter(CodeRateLimited, ratelimit.RetryAfterSeconds(wait))
		}
		// 4. Coalescing: a wake within the window of the previous one
		// is answered without a second send.
		coalesced, undo := s.coal.Begin(tk, s.now())
		if coalesced {
			outcome = "coalesced"
		} else {
			// 5. The fixed payload, synchronously.
			start := time.Now()
			res := prov.Send(sendContext(r), provider.Message{Platform: rec.Platform, Environment: rec.Environment,
				AppID: rec.AppID, Token: rec.Token})
			s.m.Observe("provider_latency_ms", float64(time.Since(start).Microseconds())/1000, dim("platform", platform))
			if e := s.sendError(platform, res); e != nil {
				undo()
				if res.Override == nil {
					outcome = res.Outcome.String()
				}
				return e
			}
			outcome = "sent"
		}
		var ans struct {
			Reseal string `json:"reseal,omitempty"`
		}
		if !current || s.cfg.Dev != nil && s.cfg.Dev.takeReseal() {
			// Sealed under a retired key: hand the vault the same
			// record under the current one (§4).
			if nb, err := s.cfg.Keys.Seal(rec); err == nil {
				ans.Reseal = nb
				s.m.Count("blob_resealed")
				if s.cfg.Dev != nil {
					s.cfg.Dev.noteReseal(nb)
				}
			}
		}
		writeJSON(w, http.StatusAccepted, ans)
		return nil
	}()
	if e != nil {
		if outcome == "" {
			outcome = e.code
		}
		s.answerError(w, e)
	}
	s.m.Count("wakes", dim("platform", platform), dim("environment", env), dim("outcome", outcome))
	if s.cfg.Dev != nil {
		s.cfg.Dev.note("wake", e)
	}
}

// sendError maps a platform outcome to the gateway's answer (§7); nil
// for a wake that was sent.
func (s *Server) sendError(platform string, res provider.Result) *apiError {
	if o := res.Override; o != nil {
		return &apiError{status: o.Status, code: o.Code, retryAfter: o.RetryAfter}
	}
	switch res.Outcome {
	case provider.Sent:
		return nil
	case provider.TokenGone:
		return fail(CodeTokenGone)
	case provider.TokenInvalid:
		return fail(CodeTokenInvalid)
	case provider.RateLimited:
		return failAfter(CodeRateLimited, res.RetryAfter)
	}
	// Unavailable, AuthFailed, Rejected: the vault retries with backoff.
	// The log line names the platform and its reason only.
	s.logError("provider/"+platform+"/"+res.Outcome.String(), "platform send failed",
		"platform", platform, "outcome", res.Outcome.String(), "detail", res.Detail)
	return failAfter(CodeProviderUnavailable, res.RetryAfter)
}

// Compile-time check: the gateway's blob limit is the vault's.
var _ = [1]struct{}{}[blob.MaxLen-pushwire.MaxBlob]
