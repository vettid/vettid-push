// Command vettid-push runs the VettID push gateway (PUSH-GATEWAY): it
// delivers contentless wake-up pushes to the VettID app through FCM and
// APNs for attested VettID vaults, and stores nothing.
//
// Configuration is by PUSH_* environment variables and three secrets
// (README.md).
//
//	vettid-push               run the gateway
//	vettid-push -dev          run the gateway stand-in of the dev stack: it accepts
//	                          the dev enclave's TEST attestation and records wakes
//	                          instead of sending them (never in production)
//	vettid-push -healthcheck  GET http://127.0.0.1:<port>/v1/health; exit 0 on 200,
//	                          1 otherwise (for the distroless image)
//	vettid-push -version      print the version
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/vettid/vettid-push/internal/config"
)

// specVersion is the PUSH-GATEWAY version this gateway implements.
const specVersion = "0.4.5"

// version is stamped at build time (-ldflags "-X main.version=..."); when
// empty, the VCS revision embedded by the Go toolchain is used.
var version string

func buildVersion() string {
	rev := version
	if rev == "" {
		rev = "unknown"
		if bi, ok := debug.ReadBuildInfo(); ok {
			rev = bi.Main.Version
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" {
					rev = s.Value
				}
			}
		}
	}
	return "vettid-push " + rev + " (PUSH-GATEWAY " + specVersion + ")"
}

func main() {
	dev := flag.Bool("dev", false, "run the dev stack's gateway stand-in (TEST attestation, wakes recorded, never sent)")
	healthcheck := flag.Bool("healthcheck", false, "probe the local /v1/health endpoint and exit 0 (healthy) or 1")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(buildVersion())
		return
	}
	cfg, err := config.Load(os.LookupEnv, *dev)
	if *healthcheck {
		os.Exit(runHealthcheck(cfg))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vettid-push: invalid configuration:", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, cfg, deps{out: os.Stdout, lookup: os.LookupEnv}); err != nil {
		fmt.Fprintln(os.Stderr, "vettid-push:", err)
		os.Exit(1)
	}
}

// runHealthcheck only needs PUSH_LISTEN_ADDR, so it works even if another
// variable fails validation (the gateway itself would not have started).
func runHealthcheck(cfg config.Config) int {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = config.Defaults().ListenAddr
	}
	u, err := cfg.HealthcheckURL()
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(u)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: status", resp.StatusCode)
		return 1
	}
	return 0
}
