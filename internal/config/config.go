// Package config loads the gateway's configuration from environment
// variables. Nothing here is secret: credentials and blob keys come from
// the secret source (internal/secrets), never from this configuration.
// Every variable is documented in README.md; keep the two in sync.
package config

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Channels.
const (
	ChannelProd    = "prod"
	ChannelStaging = "staging"
	ChannelDev     = "dev"
)

// Secret sources.
const (
	SecretsAWS  = "aws"
	SecretsFile = "file"
	SecretsEnv  = "env"
	SecretsNone = "none" // dev only: random blob keys, no credentials
)

// Config is the complete runtime configuration.
type Config struct {
	// Dev is the -dev flag: the gateway stand-in (PUSH-GATEWAY §10.4).
	Dev bool

	Channel    string // PUSH_CHANNEL: prod | staging (dev under -dev)
	ListenAddr string // PUSH_LISTEN_ADDR
	TrustProxy bool   // PUSH_TRUST_PROXY
	LogLevel   string // PUSH_LOG_LEVEL

	Platforms  []string // PUSH_PLATFORMS: fcm, apns
	FCMAppIDs  []string // PUSH_FCM_APP_IDS
	APNsAppIDs []string // PUSH_APNS_APP_IDS
	FCMProject string   // PUSH_FCM_PROJECT (else the secret's project_id)

	Secrets      string // PUSH_SECRETS: aws | file | env (| none under -dev)
	SecretPrefix string // PUSH_SECRET_PREFIX (aws): vettid-org/<channel>/push
	SecretsDir   string // PUSH_SECRETS_DIR (file)
	Region       string // AWS_REGION / AWS_DEFAULT_REGION

	MetricsNamespace string        // PUSH_METRICS_NAMESPACE
	MetricsInterval  time.Duration // PUSH_METRICS_INTERVAL
	ShutdownTimeout  time.Duration // PUSH_SHUTDOWN_TIMEOUT

	RateRegisterPerMinute int           // PUSH_RATE_REGISTER_PER_MINUTE
	RateWakePerMinute     int           // PUSH_RATE_WAKE_PER_MINUTE
	RateTokenPerHour      int           // PUSH_RATE_TOKEN_PER_HOUR
	RateTokenBurst        int           // PUSH_RATE_TOKEN_BURST
	CoalesceWindow        time.Duration // PUSH_COALESCE_WINDOW (0 disables)
	ReplayCacheMax        int           // PUSH_REPLAY_CACHE_MAX

	// -dev only.
	DevNitroRoot     string   // PUSH_DEV_NITRO_ROOT: base64 DER of the test Nitro root
	DevNitroRootFile string   // PUSH_DEV_NITRO_ROOT_FILE: the same as a PEM file
	DevPCR0s         []string // PUSH_DEV_PCR0S: accepted PCR0s (hex)
	DevControlAddr   string   // PUSH_DEV_CONTROL_ADDR ("" disables)
}

// Defaults returns the documented defaults (the limits of §8).
func Defaults() Config {
	return Config{
		ListenAddr: ":8080",
		LogLevel:   "info",
		Platforms:  []string{"fcm", "apns"},

		MetricsInterval: 60 * time.Second,
		ShutdownTimeout: 20 * time.Second,

		RateRegisterPerMinute: 30,
		RateWakePerMinute:     6000,
		RateTokenPerHour:      60,
		RateTokenBurst:        10,
		CoalesceWindow:        2 * time.Second,
		ReplayCacheMax:        200_000,
	}
}

var (
	appIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)
	pcrRE   = regexp.MustCompile(`^[0-9a-f]{96}$`)
	nsRE    = regexp.MustCompile(`^[A-Za-z0-9._/#:-]{1,255}$`)
)

func list(v string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Load builds a Config from a lookup function (os.LookupEnv in
// production); dev is the -dev flag.
func Load(lookup func(string) (string, bool), dev bool) (Config, error) {
	c := Defaults()
	c.Dev = dev
	var errs []error
	get := func(key string) (string, bool) {
		v, ok := lookup(key)
		v = strings.TrimSpace(v)
		return v, ok && v != ""
	}
	str := func(key string, dst *string) {
		if v, ok := lookup(key); ok {
			*dst = strings.TrimSpace(v)
		}
	}
	integer := func(key string, dst *int) {
		if v, ok := get(key); ok {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				errs = append(errs, fmt.Errorf("%s: want a positive integer", key))
				return
			}
			*dst = n
		}
	}
	// Durations accept Go syntax ("90s") or a bare integer of seconds.
	dur := func(key string, dst *time.Duration, zeroOK bool) {
		if v, ok := get(key); ok {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				*dst = time.Duration(n) * time.Second
			} else if d, err := time.ParseDuration(v); err == nil {
				*dst = d
			} else {
				errs = append(errs, fmt.Errorf("%s: want a duration like 60s or integer seconds", key))
				return
			}
			if *dst < 0 || *dst == 0 && !zeroOK {
				errs = append(errs, fmt.Errorf("%s: must be positive", key))
			}
		}
	}

	str("PUSH_CHANNEL", &c.Channel)
	str("PUSH_LISTEN_ADDR", &c.ListenAddr)
	if v, ok := get("PUSH_TRUST_PROXY"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, errors.New("PUSH_TRUST_PROXY: want true or false"))
		}
		c.TrustProxy = b
	}
	str("PUSH_LOG_LEVEL", &c.LogLevel)
	if v, ok := lookup("PUSH_PLATFORMS"); ok {
		c.Platforms = list(v)
	}
	if v, ok := lookup("PUSH_FCM_APP_IDS"); ok {
		c.FCMAppIDs = list(v)
	}
	if v, ok := lookup("PUSH_APNS_APP_IDS"); ok {
		c.APNsAppIDs = list(v)
	}
	str("PUSH_FCM_PROJECT", &c.FCMProject)
	str("PUSH_SECRETS", &c.Secrets)
	str("PUSH_SECRET_PREFIX", &c.SecretPrefix)
	str("PUSH_SECRETS_DIR", &c.SecretsDir)
	str("AWS_DEFAULT_REGION", &c.Region)
	if v, ok := get("AWS_REGION"); ok {
		c.Region = v
	}
	str("PUSH_METRICS_NAMESPACE", &c.MetricsNamespace)
	dur("PUSH_METRICS_INTERVAL", &c.MetricsInterval, false)
	dur("PUSH_SHUTDOWN_TIMEOUT", &c.ShutdownTimeout, false)
	integer("PUSH_RATE_REGISTER_PER_MINUTE", &c.RateRegisterPerMinute)
	integer("PUSH_RATE_WAKE_PER_MINUTE", &c.RateWakePerMinute)
	integer("PUSH_RATE_TOKEN_PER_HOUR", &c.RateTokenPerHour)
	integer("PUSH_RATE_TOKEN_BURST", &c.RateTokenBurst)
	dur("PUSH_COALESCE_WINDOW", &c.CoalesceWindow, true)
	integer("PUSH_REPLAY_CACHE_MAX", &c.ReplayCacheMax)

	str("PUSH_DEV_NITRO_ROOT", &c.DevNitroRoot)
	str("PUSH_DEV_NITRO_ROOT_FILE", &c.DevNitroRootFile)
	if v, ok := lookup("PUSH_DEV_PCR0S"); ok {
		c.DevPCR0s = list(v)
	}
	c.DevControlAddr = "127.0.0.1:8081"
	str("PUSH_DEV_CONTROL_ADDR", &c.DevControlAddr)

	// Channel-dependent defaults.
	if dev {
		if c.Channel == "" {
			c.Channel = ChannelDev
		}
		if c.Secrets == "" {
			c.Secrets = SecretsNone
		}
	} else {
		c.DevControlAddr = ""
		if c.Secrets == "" {
			c.Secrets = SecretsAWS
		}
		if _, ok := lookup("PUSH_DEV_CONTROL_ADDR"); ok || c.DevNitroRoot != "" || c.DevNitroRootFile != "" || len(c.DevPCR0s) > 0 {
			errs = append(errs, errors.New("PUSH_DEV_* variables are accepted only with -dev"))
		}
	}
	if c.SecretPrefix == "" {
		c.SecretPrefix = "vettid-org/" + c.Channel + "/push"
	}
	if c.MetricsNamespace == "" {
		c.MetricsNamespace = "vettid-org/" + c.Channel + "/push"
	}
	if err := c.Validate(); err != nil {
		errs = append(errs, err)
	}
	return c, errors.Join(errs...)
}

// Validate checks cross-field invariants.
func (c Config) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if c.Dev {
		// The stand-in accepts a test attestation: it must never carry a
		// release channel's name, blobs or credentials.
		if c.Channel != ChannelDev {
			bad("-dev: PUSH_CHANNEL must be dev or unset, not %q", c.Channel)
		}
		if c.Secrets == SecretsAWS {
			bad("-dev: PUSH_SECRETS must be none, file or env")
		}
		if c.DevNitroRoot == "" && c.DevNitroRootFile == "" {
			bad("-dev: PUSH_DEV_NITRO_ROOT or PUSH_DEV_NITRO_ROOT_FILE is required (the dev enclave's test Nitro root)")
		}
		if c.DevNitroRoot != "" && c.DevNitroRootFile != "" {
			bad("-dev: set only one of PUSH_DEV_NITRO_ROOT and PUSH_DEV_NITRO_ROOT_FILE")
		}
		for _, p := range c.DevPCR0s {
			if !pcrRE.MatchString(p) {
				bad("PUSH_DEV_PCR0S: want 96 lowercase hex digits per PCR0")
				break
			}
		}
		if c.DevControlAddr != "" && c.DevControlAddr == c.ListenAddr {
			bad("PUSH_DEV_CONTROL_ADDR must differ from PUSH_LISTEN_ADDR")
		}
	} else {
		if c.Channel != ChannelProd && c.Channel != ChannelStaging {
			bad("PUSH_CHANNEL must be prod or staging")
		}
		if c.Secrets == SecretsNone {
			bad("PUSH_SECRETS must be aws, file or env")
		}
		for _, p := range c.Platforms {
			ids := c.FCMAppIDs
			if p == "apns" {
				ids = c.APNsAppIDs
			}
			if len(ids) == 0 {
				bad("PUSH_%s_APP_IDS is required while %s is in PUSH_PLATFORMS", strings.ToUpper(p), p)
			}
		}
	}
	if c.ListenAddr == "" {
		bad("PUSH_LISTEN_ADDR must not be empty")
	}
	for _, p := range c.Platforms {
		if p != "fcm" && p != "apns" {
			bad("PUSH_PLATFORMS: unknown platform %q (want fcm, apns)", p)
		}
	}
	for _, id := range append(append([]string(nil), c.FCMAppIDs...), c.APNsAppIDs...) {
		if !appIDRE.MatchString(id) {
			bad("app ids must match [A-Za-z0-9][A-Za-z0-9._-]* (at most 255 bytes)")
			break
		}
	}
	switch c.Secrets {
	case SecretsAWS:
		if c.Region == "" {
			bad("AWS_REGION is required with PUSH_SECRETS=aws")
		}
	case SecretsFile:
		if c.SecretsDir == "" {
			bad("PUSH_SECRETS_DIR is required with PUSH_SECRETS=file")
		}
	case SecretsEnv, SecretsNone:
	default:
		bad("PUSH_SECRETS must be aws, file or env")
	}
	if !nsRE.MatchString(c.MetricsNamespace) {
		bad("PUSH_METRICS_NAMESPACE: invalid CloudWatch namespace")
	}
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		bad("PUSH_LOG_LEVEL must be debug|info|warn|error")
	}
	return errors.Join(errs...)
}

// AllowSandbox reports whether the channel accepts APNs sandbox
// registrations (§10.4: staging accepts sandbox and production;
// production only production).
func (c Config) AllowSandbox() bool { return c.Channel != ChannelProd }

// HealthcheckURL derives the loopback health URL from the listen
// address, for `vettid-push -healthcheck` inside the distroless image.
func (c Config) HealthcheckURL() (string, error) {
	_, port, err := net.SplitHostPort(c.ListenAddr)
	if err != nil {
		return "", fmt.Errorf("PUSH_LISTEN_ADDR %q: %w", c.ListenAddr, err)
	}
	if port == "" {
		port = "80"
	}
	return "http://127.0.0.1:" + port + "/v1/health", nil
}
