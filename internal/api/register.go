package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-vault/vms/pushwire"

	"github.com/vettid/vettid-push/internal/attest"
	"github.com/vettid/vettid-push/internal/blob"
	"github.com/vettid/vettid-push/internal/metrics"
	"github.com/vettid/vettid-push/internal/provider"
	"github.com/vettid/vettid-push/internal/ratelimit"
)

func dim(name, value string) metrics.Dim { return metrics.Dim{Name: name, Value: value} }

// platformDim keeps the platform dimension inside its closed set.
func platformDim(p string) string {
	if p == provider.FCM || p == provider.APNs {
		return p
	}
	return "unknown"
}

// register is POST /v1/register (§5.1).
func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	platform := "unknown"
	e := func() *apiError {
		if ok, wait := s.regAddr.Allow(addrKey(s.clientAddr(r)), s.now()); !ok {
			s.m.Count("rate_limited", dim("scope", "address_register"))
			return failAfter(CodeRateLimited, ratelimit.RetryAfterSeconds(wait))
		}
		// 1. Signature and freshness. The replay cache comes after
		// step 2: until the attestation has verified, the signer is a
		// stranger.
		sr, body, now, e := s.verify(r)
		if e != nil {
			return e
		}
		// 2. The attestation: the wake key was made by a vault release
		// of this channel, for this very request.
		digest := relayauth.Digest(http.MethodPost, r.URL.Path, sr.Timestamp, relayauth.BodyHash(body))
		if err := s.cfg.Attest.Verify(r.Header.Values(pushwire.HeaderAttestation), sr.Key, digest); err != nil {
			reason := "malformed"
			var ae *attest.Error
			if errors.As(err, &ae) {
				reason = string(ae.Reason)
			}
			s.m.Count("attestation_failures", dim("reason", reason))
			return fail(CodeAttestationInvalid)
		}
		// The replay cache, now that the key is a vault release's. It
		// is recorded whatever the answer from here on.
		if e := s.recordReplay(sr, now); e != nil {
			return e
		}
		// 3. The body.
		reg, code := s.checkRegistration(body)
		platform = platformDim(reg.Platform)
		if code != "" {
			return fail(code)
		}
		// 4. Seal. Nothing is written anywhere.
		wb, err := s.cfg.Keys.Seal(blob.Record{Platform: reg.Platform, Environment: reg.Environment,
			AppID: reg.AppID, Token: reg.Token, Key: sr.Key, Issued: s.now().Unix()})
		switch {
		case errors.Is(err, blob.ErrTooLarge):
			// A token of quotes and backslashes can double in JSON and
			// outgrow the blob (§4); no real token does.
			return fail(CodeTokenInvalid)
		case err != nil:
			s.logError("seal", "sealing a wake blob failed")
			return fail(CodeInternal)
		}
		writeJSON(w, http.StatusCreated, struct {
			WakeBlob string `json:"wake_blob"`
		}{wb})
		return nil
	}()
	outcome := "ok"
	if e != nil {
		outcome = e.code
		s.answerError(w, e)
	}
	s.m.Count("registrations", dim("platform", platform), dim("outcome", outcome))
	if s.cfg.Dev != nil {
		s.cfg.Dev.note("register", e)
	}
}

// checkRegistration applies §5.1 step 3 and names the code of a refusal
// (§7). Acceptance is decided by the vault's own strict parser
// (pushwire.ParseRegistration), so the gateway and the vault can never
// disagree about a well-formed registration.
func (s *Server) checkRegistration(body []byte) (pushwire.Registration, string) {
	reg, err := pushwire.ParseRegistration(body)
	if err != nil {
		return classify(body)
	}
	if s.cfg.Providers[reg.Platform] == nil {
		return reg, CodePlatformInvalid
	}
	if reg.Environment == provider.EnvSandbox && !s.cfg.AllowSandbox {
		return reg, CodeBadRequest
	}
	if !s.appAllowed(reg.Platform, reg.AppID) {
		return reg, CodeAppInvalid
	}
	return reg, ""
}

// classify names the code for a body the strict parser refused, checking
// in the order of §5.1 step 3: platform, token, environment, app_id.
func classify(body []byte) (pushwire.Registration, string) {
	var o map[string]json.RawMessage
	if json.Unmarshal(body, &o) != nil {
		return pushwire.Registration{}, CodeBadRequest
	}
	str := func(name string) (string, bool) {
		var v string
		raw, ok := o[name]
		if !ok || len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &v) != nil {
			return "", false
		}
		return v, true
	}
	var reg pushwire.Registration
	pl, ok := str("platform")
	if !ok {
		return reg, CodeBadRequest
	}
	if pl != provider.FCM && pl != provider.APNs {
		return reg, CodePlatformInvalid
	}
	reg.Platform = pl
	// A probe with every other member valid isolates the bad one.
	probe := func(r pushwire.Registration) bool { return r.Validate() == nil }
	env := ""
	if pl == provider.APNs {
		env = provider.EnvProduction
	}
	tok, ok := str("token")
	if !ok {
		return reg, CodeBadRequest
	}
	if !probe(pushwire.Registration{Platform: pl, Token: tok, AppID: "a", Environment: env}) {
		return reg, CodeTokenInvalid
	}
	if _, present := o["environment"]; present {
		v, ok := str("environment")
		if !ok || pl == provider.FCM || v != provider.EnvProduction && v != provider.EnvSandbox {
			return reg, CodeBadRequest
		}
	} else if pl == provider.APNs {
		return reg, CodeBadRequest
	}
	app, ok := str("app_id")
	if !ok {
		return reg, CodeBadRequest
	}
	if !probe(pushwire.Registration{Platform: pl, Token: tok, AppID: app, Environment: env}) {
		return reg, CodeAppInvalid
	}
	// Well-formed members, but the strict parser refused the object: an
	// unknown member, a duplicate name or loose JSON.
	return reg, CodeBadRequest
}
