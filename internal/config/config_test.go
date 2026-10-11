package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

var staging = map[string]string{
	"PUSH_CHANNEL":      "staging",
	"AWS_REGION":        "us-east-1",
	"PUSH_FCM_APP_IDS":  "com.vettid.app.staging",
	"PUSH_APNS_APP_IDS": "com.vettid.app.staging, com.vettid.app.staging",
}

func with(base map[string]string, kv ...string) map[string]string {
	m := map[string]string{}
	for k, v := range base {
		m[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "<unset>" {
			delete(m, kv[i])
		} else {
			m[kv[i]] = kv[i+1]
		}
	}
	return m
}

func TestDefaults(t *testing.T) {
	c, err := Load(env(staging), false)
	if err != nil {
		t.Fatal(err)
	}
	if c.Channel != "staging" || c.ListenAddr != ":8080" || c.Secrets != "aws" || c.TrustProxy ||
		c.SecretPrefix != "vettid-org/staging/push" || c.MetricsNamespace != "vettid-org/staging/push" ||
		strings.Join(c.Platforms, ",") != "fcm,apns" || len(c.APNsAppIDs) != 1 || c.DevControlAddr != "" {
		t.Fatalf("%+v", c)
	}
	// The limits of PUSH-GATEWAY §8 and §5.2.
	if c.RateRegisterPerMinute != 30 || c.RateWakePerMinute != 6000 || c.RateTokenPerHour != 60 || c.RateTokenBurst != 10 ||
		c.CoalesceWindow != 2*time.Second || c.MetricsInterval != time.Minute || c.ShutdownTimeout != 20*time.Second {
		t.Fatalf("limits %+v", c)
	}
	// §10.4: staging accepts the APNs sandbox, production does not.
	if !c.AllowSandbox() {
		t.Fatal("staging refuses sandbox")
	}
	p, err := Load(env(with(staging, "PUSH_CHANNEL", "prod")), false)
	if err != nil || p.AllowSandbox() || p.SecretPrefix != "vettid-org/prod/push" {
		t.Fatalf("prod: %+v %v", p, err)
	}
	if u, err := c.HealthcheckURL(); err != nil || u != "http://127.0.0.1:8080/v1/health" {
		t.Fatalf("%s %v", u, err)
	}
}

func TestOverrides(t *testing.T) {
	c, err := Load(env(with(staging, "PUSH_LISTEN_ADDR", "127.0.0.1:9000", "PUSH_TRUST_PROXY", "true",
		"PUSH_PLATFORMS", "apns", "PUSH_FCM_APP_IDS", "<unset>", "PUSH_SECRETS", "file", "PUSH_SECRETS_DIR", "/run/secrets",
		"PUSH_COALESCE_WINDOW", "0", "PUSH_METRICS_INTERVAL", "30", "PUSH_SHUTDOWN_TIMEOUT", "5s",
		"PUSH_RATE_TOKEN_PER_HOUR", "120", "PUSH_FCM_PROJECT", "vettid-staging", "PUSH_METRICS_NAMESPACE", "Custom/NS",
		"AWS_REGION", "<unset>", "PUSH_LOG_LEVEL", "error")), false)
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != "127.0.0.1:9000" || !c.TrustProxy || len(c.Platforms) != 1 || c.Secrets != "file" || c.CoalesceWindow != 0 ||
		c.MetricsInterval != 30*time.Second || c.ShutdownTimeout != 5*time.Second || c.RateTokenPerHour != 120 ||
		c.FCMProject != "vettid-staging" || c.MetricsNamespace != "Custom/NS" {
		t.Fatalf("%+v", c)
	}
	// No platform at all is a valid start (before any credentials exist).
	if c, err := Load(env(with(staging, "PUSH_PLATFORMS", "", "PUSH_FCM_APP_IDS", "<unset>", "PUSH_APNS_APP_IDS", "<unset>")), false); err != nil || len(c.Platforms) != 0 {
		t.Fatalf("no platforms: %v", err)
	}
}

func TestInvalid(t *testing.T) {
	cases := map[string]map[string]string{
		"no channel":                    with(staging, "PUSH_CHANNEL", "<unset>"),
		"channel dev without -dev":      with(staging, "PUSH_CHANNEL", "dev"),
		"unknown channel":               with(staging, "PUSH_CHANNEL", "production"),
		"no region with aws secrets":    with(staging, "AWS_REGION", "<unset>"),
		"no app ids for a platform":     with(staging, "PUSH_APNS_APP_IDS", "<unset>"),
		"malformed app id":              with(staging, "PUSH_FCM_APP_IDS", "com/vettid"),
		"unknown platform":              with(staging, "PUSH_PLATFORMS", "fcm,webpush"),
		"file secrets without a dir":    with(staging, "PUSH_SECRETS", "file"),
		"unknown secret source":         with(staging, "PUSH_SECRETS", "vault"),
		"secrets none without -dev":     with(staging, "PUSH_SECRETS", "none"),
		"bad boolean":                   with(staging, "PUSH_TRUST_PROXY", "maybe"),
		"bad duration":                  with(staging, "PUSH_METRICS_INTERVAL", "soon"),
		"zero interval":                 with(staging, "PUSH_METRICS_INTERVAL", "0"),
		"negative coalesce":             with(staging, "PUSH_COALESCE_WINDOW", "-1s"),
		"zero rate":                     with(staging, "PUSH_RATE_WAKE_PER_MINUTE", "0"),
		"bad log level":                 with(staging, "PUSH_LOG_LEVEL", "chatty"),
		"empty listen":                  with(staging, "PUSH_LISTEN_ADDR", ""),
		"dev root without -dev":         with(staging, "PUSH_DEV_NITRO_ROOT", "AAAA"),
		"dev pcr0s without -dev":        with(staging, "PUSH_DEV_PCR0S", strings.Repeat("ab", 48)),
		"dev control addr without -dev": with(staging, "PUSH_DEV_CONTROL_ADDR", "127.0.0.1:1"),
	}
	for name, m := range cases {
		if _, err := Load(env(m), false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// §10.4: -dev is the stand-in. It can never carry a release channel's
// name or read the release secrets.
func TestDev(t *testing.T) {
	dev := map[string]string{"PUSH_DEV_NITRO_ROOT": "AAAA", "PUSH_DEV_PCR0S": strings.Repeat("ab", 48)}
	c, err := Load(env(dev), true)
	if err != nil {
		t.Fatal(err)
	}
	if c.Channel != "dev" || c.Secrets != "none" || c.DevControlAddr != "127.0.0.1:8081" || !c.AllowSandbox() ||
		c.SecretPrefix != "vettid-org/dev/push" || len(c.DevPCR0s) != 1 {
		t.Fatalf("%+v", c)
	}
	if c, err := Load(env(with(dev, "PUSH_DEV_CONTROL_ADDR", "")), true); err != nil || c.DevControlAddr != "" {
		t.Fatalf("control listener off: %v %q", err, c.DevControlAddr)
	}
	for name, m := range map[string]map[string]string{
		"-dev on staging":         with(dev, "PUSH_CHANNEL", "staging"),
		"-dev on prod":            with(dev, "PUSH_CHANNEL", "prod"),
		"-dev with aws secrets":   with(dev, "PUSH_SECRETS", "aws", "AWS_REGION", "us-east-1"),
		"-dev without a root":     with(dev, "PUSH_DEV_NITRO_ROOT", "<unset>"),
		"-dev with two roots":     with(dev, "PUSH_DEV_NITRO_ROOT_FILE", "/x.pem"),
		"-dev with a short pcr0":  with(dev, "PUSH_DEV_PCR0S", "abcd"),
		"control on the listener": with(dev, "PUSH_DEV_CONTROL_ADDR", ":8080"),
	} {
		if _, err := Load(env(m), true); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
