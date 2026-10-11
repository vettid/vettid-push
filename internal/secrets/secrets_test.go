package secrets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSources(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "blob-keys.json"), []byte(`{"k":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fcm.json"), []byte(strings.Repeat("x", MaxSize+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	environ := map[string]string{"PUSH_SECRET_BLOB_KEYS": `{"k":1}`, "PUSH_SECRET_APNS": ""}
	sources := map[string]Source{
		"dir": Dir(dir),
		"env": Env(func(k string) (string, bool) { v, ok := environ[k]; return v, ok }),
		"map": Map{BlobKeys: []byte(`{"k":1}`)},
	}
	for name, s := range sources {
		if b, err := s.Get(ctx, BlobKeys); err != nil || string(b) != `{"k":1}` {
			t.Errorf("%s: %q %v", name, b, err)
		}
		if _, err := s.Get(ctx, APNs); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: a missing secret: %v", name, err)
		}
		// Only the three known names are ever read: no path or
		// variable can be chosen by a name.
		if _, err := s.Get(ctx, "../../etc/passwd"); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: an unknown name: %v", name, err)
		}
	}
	if _, err := Dir(dir).Get(ctx, FCM); err == nil || errors.Is(err, ErrNotFound) || len(err.Error()) > 100 {
		t.Errorf("oversized file: %v", err)
	}
	if EnvVar(BlobKeys) != "PUSH_SECRET_BLOB_KEYS" || EnvVar(FCM) != "PUSH_SECRET_FCM" || EnvVar(APNs) != "PUSH_SECRET_APNS" {
		t.Error("variable names")
	}
}
