// Package provider sends the gateway's fixed, content-free wake payloads
// to the platform push services (PUSH-GATEWAY §6) and maps their answers
// to the gateway's outcomes (§7): Firebase Cloud Messaging (HTTP v1) and
// the Apple Push Notification service (HTTP/2, token-based auth).
//
// Nothing in this package logs. Errors and results never carry a push
// token, a credential or a platform's message text: Result.Detail is
// taken from closed sets only.
package provider

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

// Platforms and APNs environments.
const (
	FCM           = "fcm"
	APNs          = "apns"
	EnvProduction = "production"
	EnvSandbox    = "sandbox"
)

// SendTimeout bounds one platform send, token refresh included (§5.2
// step 5).
const SendTimeout = 5 * time.Second

// MaxRetryAfter caps a platform's Retry-After (the vault caps at the same
// value, §7).
const MaxRetryAfter = 3600

// Message is one wake: where to send the fixed payload. It carries
// nothing else, because a wake has no content (§1).
type Message struct {
	Platform    string
	Environment string // apns only
	AppID       string
	Token       string
}

// Outcome is what the platform made of a send.
type Outcome int

// Outcomes.
const (
	// Sent: the platform accepted the message.
	Sent Outcome = iota
	// TokenGone: FCM UNREGISTERED / 404, APNs 410 (§7 token_gone).
	TokenGone
	// TokenInvalid: the platform refuses the token itself (§7
	// token_invalid).
	TokenInvalid
	// RateLimited: the platform's own 429 (§7 rate_limited).
	RateLimited
	// Unavailable: a platform 5xx, a timeout or no connection (§7
	// provider_unavailable).
	Unavailable
	// AuthFailed: the platform refuses the gateway's credentials (APNs
	// 403 InvalidProviderToken, FCM 401/403). Answered
	// provider_unavailable; it raises an alarm (§10.5).
	AuthFailed
	// Rejected: any other refusal, which a fixed payload should never
	// meet (a wrong topic, a platform change). Answered
	// provider_unavailable.
	Rejected
)

func (o Outcome) String() string {
	switch o {
	case Sent:
		return "sent"
	case TokenGone:
		return "token_gone"
	case TokenInvalid:
		return "token_invalid"
	case RateLimited:
		return "provider_rate_limited"
	case Unavailable:
		return "provider_unavailable"
	case AuthFailed:
		return "provider_auth"
	default:
		return "provider_rejected"
	}
}

// Override is an answer a dev stand-in injects in place of a send's
// outcome.
type Override struct {
	Status     int
	Code       string
	RetryAfter int
}

// Result is a send's outcome.
type Result struct {
	Outcome Outcome
	// RetryAfter is the platform's wait in seconds (0: none given).
	RetryAfter int
	// Detail names the platform's reason from a closed set ("" if none):
	// safe to log and to count.
	Detail string
	// Override, set only by the dev stand-in, is answered verbatim.
	Override *Override
}

// Provider sends wakes to one platform.
type Provider interface {
	// Send delivers the fixed payload for m. It returns when the
	// platform answered or ctx ended.
	Send(ctx context.Context, m Message) Result
}

// retryAfter reads a Retry-After header: delta-seconds or an HTTP date,
// capped at MaxRetryAfter; 0 if absent or unusable.
func retryAfter(h http.Header, now time.Time) int {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil {
		if n < 0 {
			return 0
		}
		return min(n, MaxRetryAfter)
	}
	if t, err := http.ParseTime(v); err == nil {
		d := int(t.Sub(now).Seconds())
		if d <= 0 {
			return 0
		}
		return min(d, MaxRetryAfter)
	}
	return 0
}

// pick returns s if it is in set, else other: a platform's free text
// never becomes a log field or a metric dimension.
func pick(s string, set []string, other string) string {
	for _, x := range set {
		if x == s {
			return x
		}
	}
	return other
}
