// Package secrets reads the gateway's three secrets at start (PUSH-GATEWAY
// §10.2): the APNs key, the FCM access configuration and the blob keys.
// Nothing is ever written back.
//
// A Source hands out a secret's bytes by its short name. The AWS Secrets
// Manager source lives in internal/awsx; this package holds the sources
// for development and tests. No source logs, and no error carries a
// secret's content.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The secrets' short names: the last element of their Secrets Manager
// names, vettid-org/<stage>/push/<name>.
const (
	APNs     = "apns"
	FCM      = "fcm"
	BlobKeys = "blob-keys"
)

// MaxSize bounds a secret (Secrets Manager's own limit is 64 KiB).
const MaxSize = 64 << 10

// ErrNotFound is a secret the source does not have.
var ErrNotFound = errors.New("secrets: not found")

// Source reads secrets.
type Source interface {
	// Get returns the secret's bytes: a JSON document.
	Get(ctx context.Context, name string) ([]byte, error)
}

func known(name string) bool { return name == APNs || name == FCM || name == BlobKeys }

// Dir reads <dir>/<name>.json (development, and deployments that mount
// secrets as files).
type Dir string

// Get implements Source.
func (d Dir) Get(_ context.Context, name string) ([]byte, error) {
	if !known(name) {
		return nil, ErrNotFound
	}
	b, err := os.ReadFile(filepath.Join(string(d), name+".json"))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, ErrNotFound
	case err != nil:
		return nil, fmt.Errorf("secrets: reading %s.json failed", name)
	case len(b) > MaxSize:
		return nil, fmt.Errorf("secrets: %s.json is too large", name)
	}
	return b, nil
}

// EnvVar is the variable the Env source reads for a secret:
// PUSH_SECRET_APNS, PUSH_SECRET_FCM, PUSH_SECRET_BLOB_KEYS.
func EnvVar(name string) string {
	return "PUSH_SECRET_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
}

// Env reads each secret from its environment variable (tests, and
// platforms that inject secrets into the environment).
type Env func(string) (string, bool)

// Get implements Source.
func (e Env) Get(_ context.Context, name string) ([]byte, error) {
	if !known(name) {
		return nil, ErrNotFound
	}
	v, ok := e(EnvVar(name))
	if !ok || v == "" {
		return nil, ErrNotFound
	}
	if len(v) > MaxSize {
		return nil, fmt.Errorf("secrets: %s is too large", EnvVar(name))
	}
	return []byte(v), nil
}

// Map is an in-memory source (tests).
type Map map[string][]byte

// Get implements Source.
func (m Map) Get(_ context.Context, name string) ([]byte, error) {
	b, ok := m[name]
	if !ok {
		return nil, ErrNotFound
	}
	return b, nil
}
