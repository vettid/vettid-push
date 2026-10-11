package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/vettid/vettid-push/internal/api"
	"github.com/vettid/vettid-push/internal/attest"
	"github.com/vettid/vettid-push/internal/awsx"
	"github.com/vettid/vettid-push/internal/blob"
	"github.com/vettid/vettid-push/internal/config"
	"github.com/vettid/vettid-push/internal/metrics"
	"github.com/vettid/vettid-push/internal/provider"
	"github.com/vettid/vettid-push/internal/secrets"
)

// deps are run's injection points; main passes the real ones.
type deps struct {
	// out receives the log and the metric lines (stdout: the task's
	// CloudWatch log group).
	out io.Writer
	// lookup reads the environment (the env secret source).
	lookup func(string) (string, bool)
	// ready, if set, receives the public and control listen addresses
	// once the gateway accepts connections.
	ready chan<- [2]string

	// Test replacements: a secret source, the manifest trust, the Nitro
	// roots and the providers. Nil in production.
	secrets   secrets.Source
	trust     *attest.Trust
	roots     *x509.CertPool
	providers func(platform string, secret []byte) (provider.Provider, string, error)
}

func newLogger(level string, out io.Writer) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{Level: l}))
}

// syncWriter serializes the log and the metric lines on one stream.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(b)
}

// devRoots reads the dev enclave's test Nitro root (-dev only).
func devRoots(cfg config.Config) (*x509.CertPool, error) {
	var der []byte
	if cfg.DevNitroRootFile != "" {
		b, err := os.ReadFile(cfg.DevNitroRootFile)
		if err != nil {
			return nil, errors.New("PUSH_DEV_NITRO_ROOT_FILE: cannot read the file")
		}
		blk, _ := pem.Decode(b)
		if blk == nil || blk.Type != "CERTIFICATE" {
			return nil, errors.New("PUSH_DEV_NITRO_ROOT_FILE: want a PEM certificate")
		}
		der = blk.Bytes
	} else {
		b, err := base64.StdEncoding.DecodeString(cfg.DevNitroRoot)
		if err != nil {
			return nil, errors.New("PUSH_DEV_NITRO_ROOT: want the base64 DER of a certificate")
		}
		der = b
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.New("the dev Nitro root is not a certificate")
	}
	// The stand-in must never be anchored to the real root: with it, a
	// "dev" gateway would be a gateway that skips the manifest.
	if c.Equal(attest.NitroRoot()) {
		return nil, errors.New("-dev refuses the AWS Nitro Enclaves root: the stand-in takes the dev enclave's TEST root only")
	}
	p := x509.NewCertPool()
	p.AddCert(c)
	return p, nil
}

// run serves until ctx ends (SIGTERM/SIGINT in production), then drains
// within cfg.ShutdownTimeout.
func run(ctx context.Context, cfg config.Config, d deps) error {
	out := &syncWriter{w: d.out}
	logger := newLogger(cfg.LogLevel, out)
	reg := metrics.New(cfg.MetricsNamespace, nil)

	startCtx, cancelStart := context.WithTimeout(ctx, 30*time.Second)
	defer cancelStart()

	// Secrets: read once, at start; nothing is written back (§10.2).
	src := d.secrets
	var awsCfg *aws.Config
	if src == nil {
		switch cfg.Secrets {
		case config.SecretsAWS:
			ac, err := awsx.Load(startCtx, cfg.Region)
			if err != nil {
				return fmt.Errorf("aws configuration: %w", err)
			}
			awsCfg = &ac
			src = awsx.NewSecretsManager(ac, cfg.SecretPrefix, "")
		case config.SecretsFile:
			src = secrets.Dir(cfg.SecretsDir)
		case config.SecretsEnv:
			src = secrets.Env(d.lookup)
		}
	}

	// Blob keys.
	var keys *blob.Keyring
	if src == nil {
		// -dev without secrets: a random key, as the vault's test
		// stand-in has; blobs do not survive a restart.
		k, err := blob.NewRandomKeyring(cfg.Channel)
		if err != nil {
			return err
		}
		keys = k
	} else {
		raw, err := src.Get(startCtx, secrets.BlobKeys)
		if err != nil {
			return fmt.Errorf("blob keys: %w", err)
		}
		k, err := blob.NewKeyring(cfg.Channel, raw)
		clear(raw)
		if err != nil {
			return err
		}
		keys = k
	}
	keyIDs, currentKey := keys.KeyIDs()

	// Attestation trust.
	verifier := &attest.Verifier{}
	var manifests *attest.Manifests
	var dev *api.Dev
	if cfg.Dev {
		roots, err := devRoots(cfg)
		if err != nil {
			return err
		}
		verifier.Roots, verifier.Releases = roots, attest.StaticReleases(cfg.DevPCR0s)
		dev = api.NewDev(nil)
	} else {
		trust, err := attest.TrustFor(cfg.Channel)
		if d.trust != nil {
			trust, err = *d.trust, nil
		}
		if err != nil {
			return err
		}
		manifests = &attest.Manifests{URL: trust.ManifestURL, Keys: trust.ManifestKeys}
		verifier.Roots, verifier.Releases = attest.NitroRoots(), manifests
		if d.roots != nil {
			verifier.Roots = d.roots
		}
	}

	// Providers.
	providers := map[string]provider.Provider{}
	kinds := map[string]string{}
	for _, p := range cfg.Platforms {
		if cfg.Dev {
			providers[p], kinds[p] = dev, "recorded"
			continue
		}
		raw, err := src.Get(startCtx, p)
		if err != nil {
			return fmt.Errorf("%s secret: %w", p, err)
		}
		build := d.providers
		if build == nil {
			build = func(platform string, secret []byte) (provider.Provider, string, error) {
				return buildProvider(startCtx, cfg, awsCfg, platform, secret)
			}
		}
		prov, kind, err := build(p, raw)
		clear(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		providers[p], kinds[p] = prov, kind
	}

	apiCfg := api.Config{
		Channel: cfg.Channel, Keys: keys, Attest: verifier, Providers: providers,
		AllowSandbox: cfg.AllowSandbox(), TrustProxy: cfg.TrustProxy, Metrics: reg, Log: logger, Dev: dev,
		Limits: api.Limits{RegisterPerMinute: cfg.RateRegisterPerMinute, WakePerMinute: cfg.RateWakePerMinute,
			TokenPerHour: cfg.RateTokenPerHour, TokenBurst: cfg.RateTokenBurst, Coalesce: cfg.CoalesceWindow,
			ReplayCacheMax: cfg.ReplayCacheMax},
	}
	if !cfg.Dev || len(cfg.FCMAppIDs)+len(cfg.APNsAppIDs) > 0 {
		apiCfg.AppIDs = map[string][]string{provider.FCM: cfg.FCMAppIDs, provider.APNs: cfg.APNsAppIDs}
	}
	srv, err := api.New(apiCfg)
	if err != nil {
		return err
	}

	// Background work: manifest refresh, sweeps, metric flushes.
	bg, stopBG := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	defer func() { stopBG(); wg.Wait(); _ = reg.Flush(out) }()
	if manifests != nil {
		notPublished := false
		report := func(err error) {
			if errors.Is(err, attest.ErrNotPublished) && manifests.Serial() == 0 {
				// A channel before its first release serves no manifest
				// (VAULT-RELEASES §7): no release exists that could
				// register. Said once, not every minute.
				reg.Count("manifest_refresh", metrics.Dim{Name: "outcome", Value: "not_published"})
				if !notPublished {
					notPublished = true
					logger.Warn("no release manifest is published for this channel yet; registrations are refused until one is")
				}
				return
			}
			if err != nil {
				reg.Count("manifest_refresh", metrics.Dim{Name: "outcome", Value: "error"})
				logger.Error("manifest refresh failed", "err", err.Error(), "trusted_serial", manifests.Serial())
				return
			}
			reg.Count("manifest_refresh", metrics.Dim{Name: "outcome", Value: "ok"})
		}
		// The first fetch is part of the start. If it fails the gateway
		// still starts: wakes need no manifest, registrations are refused
		// until a refresh succeeds.
		report(manifests.Refresh(startCtx))
		wg.Add(1)
		go func() { defer wg.Done(); manifests.Run(bg, attest.RefreshInterval, report) }()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		sweep, flush := time.NewTicker(30*time.Second), time.NewTicker(cfg.MetricsInterval)
		defer sweep.Stop()
		defer flush.Stop()
		for {
			select {
			case <-bg.Done():
				return
			case <-sweep.C:
				srv.Sweep()
			case <-flush.C:
				_ = reg.Flush(out)
			}
		}
	}()

	pub := &http.Server{
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		// The attestation header alone is about 6 KiB (at most 44 KiB).
		MaxHeaderBytes: 64 << 10,
		// net/http's own error lines name the peer's address; the
		// gateway logs no source address (§10.5).
		ErrorLog: log.New(io.Discard, "", 0),
	}
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return err
	}
	errc := make(chan error, 2)
	go func() { errc <- pub.Serve(ln) }()

	var ctl *http.Server
	ctlAddr := ""
	if dev != nil && cfg.DevControlAddr != "" {
		cln, err := net.Listen("tcp", cfg.DevControlAddr)
		if err != nil {
			pub.Close()
			return fmt.Errorf("dev control listener: %w", err)
		}
		ctlAddr = cln.Addr().String()
		ctl = &http.Server{Handler: dev.ControlHandler(), ReadHeaderTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
		go func() { errc <- ctl.Serve(cln) }()
	}

	start := []any{"version", buildVersion(), "channel", cfg.Channel, "listen", cfg.ListenAddr,
		"trust_proxy", cfg.TrustProxy, "secrets", cfg.Secrets, "platforms", strings.Join(cfg.Platforms, ","),
		"blob_keys", len(keyIDs), "blob_key_current", currentKey, "apns_sandbox", cfg.AllowSandbox()}
	for _, p := range cfg.Platforms {
		start = append(start, p+"_access", kinds[p])
	}
	if manifests != nil {
		start = append(start, "manifest_url", manifests.URL, "manifest_serial", manifests.Serial())
	}
	if cfg.Dev {
		logger.Warn("DEV STAND-IN: test attestation accepted, wakes are recorded and never sent; not for production",
			append(start, "dev_control", ctlAddr, "dev_pcr0s", len(cfg.DevPCR0s))...)
	} else {
		logger.Info("push gateway started", start...)
	}
	if d.ready != nil {
		d.ready <- [2]string{ln.Addr().String(), ctlAddr}
	}

	var runErr error
	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received; draining", "timeout", cfg.ShutdownTimeout.String())
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	}
	// Bounded drain: in-flight requests (a platform send takes at most
	// 5 s) finish, then background work stops and the last metrics are
	// flushed (deferred above).
	sctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if ctl != nil {
		ctl.Close()
	}
	if err := pub.Shutdown(sctx); err != nil {
		logger.Warn("http shutdown incomplete; closing remaining connections")
		pub.Close()
	}
	logger.Info("push gateway stopped")
	return runErr
}

// buildProvider makes a platform's client from its secret (§10.2).
func buildProvider(ctx context.Context, cfg config.Config, awsCfg *aws.Config, platform string, secret []byte) (provider.Provider, string, error) {
	switch platform {
	case provider.APNs:
		c, err := provider.NewAPNsClient(secret)
		return c, "p8_key", err
	case provider.FCM:
		o := provider.FCMAuthOptions{Region: cfg.Region}
		if awsCfg == nil && cfg.Region != "" {
			// Federation needs the task role even when the secrets
			// come from files or the environment.
			if ac, err := awsx.Load(ctx, cfg.Region); err == nil {
				awsCfg = &ac
			}
		}
		if awsCfg != nil {
			o.AWSCredentials = awsx.Credentials(*awsCfg)
		}
		ts, kind, project, err := provider.NewFCMTokenSource(secret, o)
		if err != nil {
			return nil, "", err
		}
		if cfg.FCMProject != "" {
			project = cfg.FCMProject
		}
		if project == "" {
			return nil, "", errors.New("no Firebase project: set PUSH_FCM_PROJECT or project_id in the fcm secret")
		}
		return &provider.FCMClient{Project: project, Tokens: ts, HTTP: &http.Client{Timeout: provider.SendTimeout + time.Second}}, string(kind), nil
	}
	return nil, "", errors.New("unknown platform")
}
