package api

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// Error codes (PUSH-GATEWAY §7; grammar of Relay Protocol §7.1).
const (
	CodeSignatureInvalid    = "signature_invalid"
	CodeTimestampStale      = "timestamp_stale"
	CodeReplayDetected      = "replay_detected"
	CodeAttestationInvalid  = "attestation_invalid"
	CodeBadRequest          = "bad_request"
	CodePlatformInvalid     = "platform_invalid"
	CodeAppInvalid          = "app_invalid"
	CodeTokenInvalid        = "token_invalid"
	CodeTokenGone           = "token_gone"
	CodeBlobInvalid         = "blob_invalid"
	CodeRateLimited         = "rate_limited"
	CodeProviderUnavailable = "provider_unavailable"
	CodeInternal            = "internal"
	CodeNotFound            = "not_found"
)

// statusFor maps a code to its HTTP status exactly as the §7 table does.
func statusFor(code string) int {
	switch code {
	case CodeSignatureInvalid, CodeTimestampStale, CodeReplayDetected:
		return http.StatusUnauthorized
	case CodeAttestationInvalid:
		return http.StatusForbidden
	case CodeBadRequest, CodePlatformInvalid, CodeAppInvalid, CodeTokenInvalid:
		return http.StatusBadRequest
	case CodeTokenGone, CodeBlobInvalid:
		return http.StatusGone
	case CodeRateLimited:
		return http.StatusTooManyRequests
	case CodeProviderUnavailable:
		return http.StatusBadGateway
	case CodeNotFound:
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}

// messages are fixed per code: an error body never echoes request
// content (no token, blob, key or app id).
var messages = map[string]string{
	CodeSignatureInvalid:    "request signature invalid",
	CodeTimestampStale:      "request timestamp outside the freshness window",
	CodeReplayDetected:      "request replay detected",
	CodeAttestationInvalid:  "attestation invalid",
	CodeBadRequest:          "malformed request",
	CodePlatformInvalid:     "platform unknown",
	CodeAppInvalid:          "app id not accepted",
	CodeTokenInvalid:        "push token invalid",
	CodeTokenGone:           "push token no longer registered",
	CodeBlobInvalid:         "wake blob invalid",
	CodeRateLimited:         "rate limited",
	CodeProviderUnavailable: "push provider unavailable",
	CodeInternal:            "internal error",
	CodeNotFound:            "not found",
}

type errorBody struct {
	Code       string `json:"code"`
	Message    string `json:"message,omitempty"`
	RetryAfter int    `json:"retry_after,omitempty"`
}

// apiError is one error answer.
type apiError struct {
	status     int
	code       string
	retryAfter int
}

func fail(code string) *apiError { return &apiError{status: statusFor(code), code: code} }

func failAfter(code string, retryAfter int) *apiError {
	return &apiError{status: statusFor(code), code: code, retryAfter: retryAfter}
}

// writeError renders the error body; a wait goes into the body's
// retry_after and the Retry-After header (§7).
func writeError(w http.ResponseWriter, e *apiError) {
	if e.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(e.retryAfter))
	}
	writeJSON(w, e.status, errorBody{Code: e.code, Message: messages[e.code], RetryAfter: e.retryAfter})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
