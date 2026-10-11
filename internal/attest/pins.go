package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"errors"

	"github.com/vettid/vettid-vault/vms/nitro"
	"github.com/vettid/vettid-vault/vms/pins"
)

// Channels.
const (
	ChannelProd    = "prod"
	ChannelStaging = "staging"
	ChannelDev     = "dev"
)

// Trust is what a channel's gateway pins (PUSH-GATEWAY §10.4): the
// manifest URL and the manifest keys. They are compiled in, like the
// pins of a vault release (vettid-vault enclave/releasecfg/<channel>.json,
// vettid.org lib/config.ts manifestKeys); no configuration changes them.
type Trust struct {
	ManifestURL  string
	ManifestKeys []*ecdsa.PublicKey
}

// The manifest keys, as base64 SubjectPublicKeyInfo (ECDSA P-256).
const (
	// Production key A: KMS, alias/vettid-org-vault-manifest; key_id
	// 4353463f85c4012f.
	prodKeyA = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7xDU6CSVsFDJvP7UXigsN9SDB+KIppU85Y3DRvo0oMQZYKHZ1S/3OaNdFk2/HJX+hohYdyU6QIFPXiDBirflCQ=="
	// Production key B: the offline standby; key_id 1abd49da96970b6e.
	prodKeyB = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIcIodW3liYaxACuOdB0If8igq/oWfVOcLGbWTy1vUNzTlvsVNe3ljfqpqfTCZwtR611EYk7UPTCfjaEEMPLxfQ=="
	// The staging key: KMS, alias/vettid-org-staging-vault-manifest;
	// key_id e9b3a403423120ac.
	stagingKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEok8gqeC5VcGx4KL+B5fL7UgENBXf+59RigkR0TZ0NqjiWM2VK6V1+paNoqRTBx7nXXN3L/2ehjsTb31GGVkEAw=="
)

// Manifest URLs (VAULT-RELEASES §3.1).
const (
	prodManifestURL    = "https://vettid.org/.well-known/vettid/pcr-manifest.json"
	stagingManifestURL = "https://staging.vettid.org/.well-known/vettid/pcr-manifest.json"
)

// ErrChannel is a channel without pins (dev pins nothing here).
var ErrChannel = errors.New("attest: no pins for this channel")

// ParseManifestKey parses a base64 SubjectPublicKeyInfo of an ECDSA P-256
// key.
func ParseManifestKey(b64 string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil {
		return nil, errors.New("attest: manifest key is not base64")
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New("attest: manifest key is not a SubjectPublicKeyInfo")
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("attest: manifest key is not ECDSA P-256")
	}
	return pub, nil
}

// TrustFor returns the pins of a release channel: production pins keys A
// and B, staging the staging key.
func TrustFor(channel string) (Trust, error) {
	var url string
	var b64 []string
	switch channel {
	case ChannelProd:
		url, b64 = prodManifestURL, []string{prodKeyA, prodKeyB}
	case ChannelStaging:
		url, b64 = stagingManifestURL, []string{stagingKey}
	default:
		return Trust{}, ErrChannel
	}
	t := Trust{ManifestURL: url}
	for _, s := range b64 {
		k, err := ParseManifestKey(s)
		if err != nil {
			return Trust{}, err
		}
		t.ManifestKeys = append(t.ManifestKeys, k)
	}
	return t, nil
}

// NitroRoot is the pinned AWS Nitro Enclaves root (the vault's pin,
// vettid-vault vms/pins).
func NitroRoot() *x509.Certificate { return pins.NitroRoot() }

// NitroRoots returns a pool with the pinned AWS Nitro Enclaves root only.
func NitroRoots() *x509.CertPool { return nitro.Pool(pins.NitroRoot()) }
