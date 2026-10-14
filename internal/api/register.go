package api

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

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

// register is POST /v1/register (§5.1, first step). It does not return
// the wake blob: it sends a challenge code to the push token and answers
// with a pending registration, which POST /v1/confirm exchanges for the
// blob once the vault returns the code its app received.
func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	platform, challenge := "unknown", ""
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
		// 4. The token's challenge limit, apart from its wakes.
		rec := blob.Record{Platform: reg.Platform, Environment: reg.Environment,
			AppID: reg.AppID, Token: reg.Token, Key: sr.Key, Issued: s.now().Unix()}
		if ok, wait := s.chal.Allow(s.tokenKey(rec), s.now()); !ok {
			s.m.Count("rate_limited", dim("scope", "challenge"))
			return failAfter(CodeRateLimited, ratelimit.RetryAfterSeconds(wait))
		}
		// 5. Seal the pending registration with a fresh challenge
		// code. Nothing is written anywhere; the code leaves only in
		// the pending registration, which only the gateway opens, and
		// in the push to the token.
		code, err := newChallengeCode()
		if err != nil {
			s.logError("challenge", "making a challenge code failed")
			return fail(CodeInternal)
		}
		pending, err := s.cfg.Keys.SealPending(rec, code)
		switch {
		case errors.Is(err, blob.ErrTooLarge):
			// A token of quotes and backslashes can double in JSON and
			// outgrow the blob (§4); no real token does.
			return fail(CodeTokenInvalid)
		case err != nil:
			s.logError("seal", "sealing a wake blob failed")
			return fail(CodeInternal)
		}
		// 6. Send the challenge to the token, synchronously. Only the
		// app that holds the token receives the code, and the blob is
		// issued only for it (POST /v1/confirm).
		prov := s.cfg.Providers[reg.Platform]
		start := time.Now()
		res := prov.Send(sendContext(r), provider.Message{Platform: reg.Platform, Environment: reg.Environment,
			AppID: reg.AppID, Token: reg.Token, Challenge: code})
		s.m.Observe("provider_latency_ms", float64(time.Since(start).Microseconds())/1000, dim("platform", platform))
		challenge = res.Outcome.String()
		if e := s.sendError(platform, res); e != nil {
			if res.Override != nil {
				challenge = e.code
			}
			return e
		}
		writeJSON(w, http.StatusAccepted, struct {
			Pending string `json:"pending"`
		}{pending})
		return nil
	}()
	outcome := "ok"
	if e != nil {
		outcome = e.code
		s.answerError(w, e)
	}
	s.m.Count("registrations", dim("platform", platform), dim("outcome", outcome))
	if challenge != "" {
		s.m.Count("challenges", dim("platform", platform), dim("outcome", challenge))
	}
	if s.cfg.Dev != nil {
		s.cfg.Dev.note("register", e)
	}
}

// newChallengeCode returns a fresh challenge code: 16 random bytes,
// base64url without padding (22 characters).
func newChallengeCode() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// confirm is POST /v1/confirm (§5.1, second step): the vault returns the
// challenge code that its app received by push, with the pending
// registration, signed by the registration's wake key. Only then is the
// wake blob issued: whoever cannot receive pushes for the token never
// gets one.
func (s *Server) confirm(w http.ResponseWriter, r *http.Request) {
	platform := "unknown"
	e := func() *apiError {
		if ok, wait := s.conAddr.Allow(addrKey(s.clientAddr(r)), s.now()); !ok {
			s.m.Count("rate_limited", dim("scope", "address_confirm"))
			return failAfter(CodeRateLimited, ratelimit.RetryAfterSeconds(wait))
		}
		// 1. Signature and freshness, then the body.
		sr, body, now, e := s.verify(r)
		if e != nil {
			return e
		}
		pending, code, ok := parseConfirm(body)
		if !ok {
			return fail(CodeBadRequest)
		}
		// 2. Open the pending registration: its key must be the
		// signer, it must be younger than the challenge's life, and
		// the code must be the one sent to the token. Every failure is
		// the same challenge_invalid (no oracle).
		rec, want, err := s.cfg.Keys.OpenPending(pending)
		if err != nil || subtle.ConstantTimeCompare(rec.Key, sr.Key) != 1 {
			return fail(CodeChallengeInvalid)
		}
		if age := now.Unix() - rec.Issued; age < 0 || age > int64(provider.ChallengeLife/time.Second) {
			return fail(CodeChallengeInvalid)
		}
		if subtle.ConstantTimeCompare([]byte(code), []byte(want)) != 1 {
			return fail(CodeChallengeInvalid)
		}
		// A record this gateway would no longer seal is refused, as at
		// a wake.
		if s.cfg.Providers[rec.Platform] == nil || !s.appAllowed(rec.Platform, rec.AppID) ||
			rec.Environment == provider.EnvSandbox && !s.cfg.AllowSandbox {
			return fail(CodeChallengeInvalid)
		}
		platform = platformDim(rec.Platform)
		// The replay cache, now that the request is a pending
		// registration's key's.
		if e := s.recordReplay(sr, now); e != nil {
			return e
		}
		// 3. Seal the wake blob; its age counts from now (§4).
		rec.Issued = s.now().Unix()
		wb, err := s.cfg.Keys.Seal(rec)
		if err != nil {
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
	s.m.Count("confirmations", dim("platform", platform), dim("outcome", outcome))
	if s.cfg.Dev != nil {
		s.cfg.Dev.note("confirm", e)
	}
}

// parseConfirm parses {"pending": "...", "code": "..."} strictly: one
// JSON object with exactly these two string members.
func parseConfirm(body []byte) (pending, code string, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var in struct {
		Pending *string `json:"pending"`
		Code    *string `json:"code"`
	}
	if dec.Decode(&in) != nil || in.Pending == nil || in.Code == nil {
		return "", "", false
	}
	if _, err := dec.Token(); err != io.EOF {
		return "", "", false
	}
	if !duplicateFree(body) || len(*in.Code) == 0 || len(*in.Code) > 64 || len(*in.Pending) == 0 || len(*in.Pending) > blob.MaxLen {
		return "", "", false
	}
	return *in.Pending, *in.Code, true
}

// duplicateFree reports whether the top-level object names each member
// once (encoding/json keeps the last of a repeated name).
func duplicateFree(body []byte) bool {
	var o map[string]json.RawMessage
	if json.Unmarshal(body, &o) != nil {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return false
	}
	n := 0
	for dec.More() {
		if _, err := dec.Token(); err != nil {
			return false
		}
		var v json.RawMessage
		if dec.Decode(&v) != nil {
			return false
		}
		n++
	}
	return n == len(o)
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
