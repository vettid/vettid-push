// Package nsmtest is TEST-ONLY support: a fake Nitro Security Module with
// its own throwaway PKI, which signs attestation documents in the NSM's
// encoding (an untagged COSE_Sign1, ES384), and a signer of release
// manifests. Every key is generated when the test runs; nothing here is a
// fixture. The gateway binary never links this package
// (cmd/vettid-push's dependency test).
package nsmtest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"time"

	"github.com/vettid/vettid-vault/vms/manifest"
)

// NSM is a fake Nitro Security Module.
type NSM struct {
	Root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	inter    *x509.Certificate
	leaf     *x509.Certificate
	leafKey  *ecdsa.PrivateKey
	PCRs     map[uint64][]byte
	Now      func() time.Time
	ModuleID string
}

// PCR returns a 48-byte PCR value, all bytes b.
func PCR(b byte) []byte { return bytes.Repeat([]byte{b}, 48) }

// PCRHex is PCR as lowercase hex.
func PCRHex(b byte) string { return hex.EncodeToString(PCR(b)) }

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// New returns a fake NSM with a fresh PKI (root, intermediate, leaf, all
// P-384) whose PCR0, PCR1 and PCR2 are 48 bytes of p0, p0+1 and p0+2.
func New(p0 byte, now func() time.Time) *NSM {
	if now == nil {
		now = time.Now
	}
	n := &NSM{Now: now, ModuleID: "i-0000000000000000-enc0000000000000000",
		PCRs: map[uint64][]byte{0: PCR(p0), 1: PCR(p0 + 1), 2: PCR(p0 + 2)}}
	nb, na := now().Add(-24*time.Hour), now().Add(24*time.Hour)
	n.rootKey = must(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
	rootT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TEST nitro root"},
		NotBefore: nb, NotAfter: na, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	n.Root = must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, rootT, rootT, &n.rootKey.PublicKey, n.rootKey))))
	interKey := must(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
	interT := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "TEST nitro intermediate"},
		NotBefore: nb, NotAfter: na, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	n.inter = must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, interT, n.Root, &interKey.PublicKey, n.rootKey))))
	n.leafKey = must(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
	leafT := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "TEST " + n.ModuleID},
		NotBefore: nb, NotAfter: na, KeyUsage: x509.KeyUsageDigitalSignature}
	n.leaf = must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, leafT, n.inter, &n.leafKey.PublicKey, interKey))))
	return n
}

// Roots returns a pool with this NSM's root.
func (n *NSM) Roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(n.Root)
	return p
}

// PCR0Hex is this NSM's PCR0.
func (n *NSM) PCR0Hex() string { return hex.EncodeToString(n.PCRs[0]) }

// Attest returns an attestation document with the given user_data, nonce
// and public_key (nil: null), as the NSM encodes it.
func (n *NSM) Attest(userData, nonce, publicKey []byte) ([]byte, error) {
	return n.AttestAt(n.Now(), userData, nonce, publicKey), nil
}

// AttestAt is Attest with the document's timestamp set to at.
func (n *NSM) AttestAt(at time.Time, userData, nonce, publicKey []byte) []byte {
	var p enc
	p.head(5, 9)
	p.text("module_id").text(n.ModuleID)
	p.text("digest").text("SHA384")
	p.text("timestamp").uint(uint64(at.UnixMilli()))
	p.text("pcrs").head(5, uint64(len(n.PCRs)))
	for i := uint64(0); i < 32; i++ {
		if v, ok := n.PCRs[i]; ok {
			p.uint(i).bytes(v)
		}
	}
	p.text("certificate").bytes(n.leaf.Raw)
	p.text("cabundle").head(4, 2).bytes(n.Root.Raw).bytes(n.inter.Raw)
	p.text("public_key").opt(publicKey)
	p.text("user_data").opt(userData)
	p.text("nonce").opt(nonce)
	payload := p.b

	protected := []byte{0xa1, 0x01, 0x38, 0x22} // {1: -35} (ES384)
	var ss enc
	ss.head(4, 4).text("Signature1").bytes(protected).bytes(nil).bytes(payload)
	digest := sha512.Sum384(ss.b)
	r, s := must2(ecdsa.Sign(rand.Reader, n.leafKey, digest[:]))
	sig := make([]byte, 96)
	r.FillBytes(sig[:48])
	s.FillBytes(sig[48:])

	var d enc
	d.head(4, 4).bytes(protected).head(5, 0).bytes(payload).bytes(sig)
	return d.b
}

func must2(r, s *big.Int, err error) (*big.Int, *big.Int) {
	if err != nil {
		panic(err)
	}
	return r, s
}

// Attester adapts the NSM to the vault client's hook (pushwire.Client
// Attest): public_key = the wake key, user_data = the request's digest.
func (n *NSM) Attester() func(ed25519.PublicKey, [32]byte) ([]byte, error) {
	return func(pub ed25519.PublicKey, digest [32]byte) ([]byte, error) {
		return n.Attest(digest[:], nil, pub)
	}
}

// Header returns the X-VettID-Attestation value for a document.
func Header(doc []byte) string { return base64.StdEncoding.EncodeToString(doc) }

// enc is a minimal CBOR encoder (definite lengths).
type enc struct{ b []byte }

func (e *enc) head(major byte, n uint64) *enc {
	m := major << 5
	switch {
	case n < 24:
		e.b = append(e.b, m|byte(n))
	case n < 1<<8:
		e.b = append(e.b, m|24, byte(n))
	case n < 1<<16:
		e.b = append(e.b, m|25, byte(n>>8), byte(n))
	case n < 1<<32:
		e.b = append(e.b, m|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	default:
		e.b = append(e.b, m|27, byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32), byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return e
}
func (e *enc) uint(n uint64) *enc { return e.head(0, n) }
func (e *enc) text(s string) *enc { e.head(3, uint64(len(s))); e.b = append(e.b, s...); return e }
func (e *enc) bytes(b []byte) *enc {
	e.head(2, uint64(len(b)))
	e.b = append(e.b, b...)
	return e
}
func (e *enc) opt(b []byte) *enc {
	if b == nil {
		e.b = append(e.b, 0xf6) // null
		return e
	}
	return e.bytes(b)
}

// ManifestSigner signs release manifests with a fresh P-256 key.
type ManifestSigner struct{ Key *ecdsa.PrivateKey }

// NewManifestSigner returns a signer with a fresh key.
func NewManifestSigner() *ManifestSigner {
	return &ManifestSigner{Key: must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))}
}

// Release is a manifest entry with test values around pcr0 and status.
func Release(number uint64, pcr0, status string) manifest.Release {
	return manifest.Release{Number: number, PCR0: pcr0, PCR1: PCRHex(0xe1), PCR2: PCRHex(0xe2),
		SealKey: "arn:aws:kms:us-east-1:000000000000:key/test", Status: status,
		PublishedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Notes: "https://example.test/releases/"}
}

// Served returns the served document of a manifest with the given serial
// and releases.
func (s *ManifestSigner) Served(serial uint64, releases ...manifest.Release) []byte {
	b := manifest.Build(serial, time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC), releases)
	return must(manifest.Sign(s.Key, b)).Marshal()
}

// Keys returns the signer's public key as a channel's pinned keys.
func (s *ManifestSigner) Keys() []*ecdsa.PublicKey { return []*ecdsa.PublicKey{&s.Key.PublicKey} }
