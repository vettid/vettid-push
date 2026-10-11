package attest

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/vms/manifest"
)

// RefreshInterval is how often the manifest is fetched again (§5.1).
const RefreshInterval = 10 * time.Minute

// Manifest refresh errors.
var (
	// ErrNotPublished: the manifest URL answers 404 (a channel that has
	// not published its first release serves nothing, VAULT-RELEASES §7).
	ErrNotPublished = errors.New("attest: no manifest published")
	// ErrFetch: the manifest could not be fetched.
	ErrFetch = errors.New("attest: manifest fetch failed")
	// ErrRollback: the served manifest has a lower serial than one
	// already trusted, or the same serial with other bytes.
	ErrRollback = errors.New("attest: manifest serial rollback")
)

// Manifests fetches, verifies and holds a channel's release manifest. The
// zero serial means none has been trusted yet; the serial rule lives in
// memory only (the gateway keeps no state across restarts).
type Manifests struct {
	// URL is the channel's manifest URL.
	URL string
	// Keys are the channel's pinned manifest keys (the served document's
	// key_id selects one).
	Keys []*ecdsa.PublicKey
	// HTTP fetches the manifest (default: a client with a 10 s timeout).
	HTTP *http.Client

	mu       sync.RWMutex
	serial   uint64
	sha      [32]byte
	admitted map[string]struct{}
}

var defaultManifestHTTP = &http.Client{Timeout: 10 * time.Second}

// Refresh fetches the manifest, verifies it with the pinned keys, applies
// the serial rule and, if all hold, trusts it. On any error the previous
// manifest stays trusted.
func (m *Manifests) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.URL, nil)
	if err != nil {
		return ErrFetch
	}
	req.Header.Set("Accept", "application/json")
	hc := m.HTTP
	if hc == nil {
		hc = defaultManifestHTTP
	}
	resp, err := hc.Do(req)
	if err != nil {
		return ErrFetch
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotPublished
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", ErrFetch, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, manifest.MaxServed+1))
	if err != nil {
		return ErrFetch
	}
	return m.Load(raw)
}

// Load verifies a served document and trusts it (Refresh without the
// fetch).
func (m *Manifests) Load(served []byte) error {
	s, err := manifest.ParseServed(served)
	if err != nil {
		return err
	}
	mf, err := manifest.Verify(s, m.Keys)
	if err != nil {
		return err
	}
	sha := sha256.Sum256(mf.Bytes)
	admitted := map[string]struct{}{}
	for _, r := range mf.Releases {
		if r.Status == manifest.StatusActive || r.Status == manifest.StatusDeprecated {
			admitted[r.PCR0] = struct{}{}
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if mf.CheckSerial(m.serial) != nil || mf.Serial == m.serial && sha != m.sha {
		return ErrRollback
	}
	m.serial, m.sha, m.admitted = mf.Serial, sha, admitted
	return nil
}

// Admits implements Releases: active and deprecated releases register.
func (m *Manifests) Admits(pcr0 string) (ok, loaded bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.serial == 0 {
		return false, false
	}
	_, ok = m.admitted[pcr0]
	return ok, true
}

// Serial returns the trusted manifest's serial (0: none yet).
func (m *Manifests) Serial() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.serial
}

// Run refreshes every interval until ctx ends, reporting each outcome to
// report (which may be nil). While no manifest is trusted yet it retries
// every minute, so a gateway that started during an outage of the site
// recovers quickly.
func (m *Manifests) Run(ctx context.Context, interval time.Duration, report func(error)) {
	for {
		wait := interval
		if m.Serial() == 0 && wait > time.Minute {
			wait = time.Minute
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := m.Refresh(rctx)
		cancel()
		if report != nil && ctx.Err() == nil {
			report(err)
		}
	}
}
