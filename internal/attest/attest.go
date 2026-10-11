// Package attest verifies the Nitro Enclaves attestation document of a
// registration (PUSH-GATEWAY §5.1 step 2) and keeps the channel's trusted
// release manifest (VAULT-MESSAGING §11.10.1).
//
// The document and manifest verifiers are the vault's own packages
// (vettid-vault vms/nitro, vms/manifest), the code apps mirror: the
// gateway verifies "exactly as apps do".
//
// Nothing in this package logs, and no error carries the document, a key
// or a PCR.
package attest

import (
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/vms/nitro"
)

// MaxAge is how far a document's timestamp may lie from now, either way
// (§5.1: "timestamp within 300 s of now").
const MaxAge = 300 * time.Second

// maxHeader bounds the base64 header value (a 32 KiB document).
var maxHeader = base64.StdEncoding.EncodedLen(nitro.MaxDocument)

// Reason names why a document was refused. The set is closed: it is the
// `reason` dimension of the attestation_failures metric (§10.5).
type Reason string

// Reasons.
const (
	ReasonMissing    Reason = "missing"     // no header, or more than one
	ReasonMalformed  Reason = "malformed"   // not base64, or not a COSE_Sign1 document
	ReasonChain      Reason = "chain"       // the certificate chain does not end at the pinned root
	ReasonSignature  Reason = "signature"   // the COSE signature does not verify
	ReasonStale      Reason = "stale"       // timestamp more than 300 s from now
	ReasonPublicKey  Reason = "public_key"  // public_key is not the request's wake key
	ReasonUserData   Reason = "user_data"   // user_data is not the request's digest
	ReasonPCR0       Reason = "pcr0"        // PCR0 is not an active or deprecated release
	ReasonNoManifest Reason = "no_manifest" // no trusted manifest has been loaded yet
	// the trusted manifest was last refreshed MaxManifestAge ago or more
	ReasonManifestStale Reason = "manifest_stale"
)

// Reasons lists every reason.
var Reasons = []Reason{ReasonMissing, ReasonMalformed, ReasonChain, ReasonSignature, ReasonStale,
	ReasonPublicKey, ReasonUserData, ReasonPCR0, ReasonNoManifest, ReasonManifestStale}

// Error is a refused document. The gateway's answer is the same
// attestation_invalid for every reason.
type Error struct{ Reason Reason }

func (e *Error) Error() string { return "attestation invalid: " + string(e.Reason) }

// Releases answers whether a PCR0 belongs to a release that may register.
type Releases interface {
	// Admits reports whether pcr0 (lowercase hex) is the PCR0 of an
	// active or deprecated release. While there is no release list to
	// answer from, ok is false and why says so: ReasonNoManifest (none
	// has been trusted yet) or ReasonManifestStale (the trusted one is
	// past its maximum age). Otherwise why is empty.
	Admits(pcr0 string) (ok bool, why Reason)
}

// Verifier checks registrations' attestation documents.
type Verifier struct {
	// Roots anchor the document's certificate chain: the pinned AWS
	// Nitro Enclaves root, or the dev enclave's test root in -dev mode.
	Roots    *x509.CertPool
	Releases Releases
	Now      func() time.Time
}

// Verify checks the X-VettID-Attestation header values of a registration
// signed by key whose canonical digest (Relay Protocol §4.1) is digest. A
// refusal is an *Error.
func (v *Verifier) Verify(header []string, key ed25519.PublicKey, digest [32]byte) error {
	if len(header) != 1 || header[0] == "" {
		return &Error{ReasonMissing}
	}
	if len(header[0]) > maxHeader {
		return &Error{ReasonMalformed}
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(header[0])
	if err != nil {
		return &Error{ReasonMalformed}
	}
	doc, err := nitro.Verify(raw, v.Roots)
	switch {
	case err == nil:
	case errors.Is(err, nitro.ErrChain), errors.Is(err, nitro.ErrNoRoots):
		return &Error{ReasonChain}
	case errors.Is(err, nitro.ErrSignature):
		return &Error{ReasonSignature}
	default:
		return &Error{ReasonMalformed}
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	if doc.CheckFresh(now(), MaxAge, MaxAge) != nil {
		return &Error{ReasonStale}
	}
	if len(key) != ed25519.PublicKeySize || len(doc.PublicKey) != ed25519.PublicKeySize ||
		subtle.ConstantTimeCompare(doc.PublicKey, key) != 1 {
		return &Error{ReasonPublicKey}
	}
	if doc.CheckUserData(digest[:]) != nil {
		return &Error{ReasonUserData}
	}
	if v.Releases == nil {
		return &Error{ReasonNoManifest}
	}
	ok, why := v.Releases.Admits(doc.PCRHex(0))
	if why != "" {
		return &Error{why}
	}
	if !ok {
		return &Error{ReasonPCR0}
	}
	return nil
}

// StaticReleases admits a fixed list of PCR0s (lowercase hex): the dev
// stand-in's releases (§10.4).
type StaticReleases []string

// Admits implements Releases.
func (s StaticReleases) Admits(pcr0 string) (bool, Reason) {
	ok := 0
	for _, p := range s {
		ok |= subtle.ConstantTimeCompare([]byte(p), []byte(pcr0))
	}
	return ok == 1 && pcr0 != "", ""
}
