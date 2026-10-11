package awsx

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/vettid/vettid-push/internal/secrets"
)

// The Secrets Manager source against a local fake of the service: the
// secret's name is vettid-org/<stage>/push/<name> (PUSH-GATEWAY §10.2),
// the request is signed with the role's credentials, and a missing
// secret is ErrNotFound. No AWS endpoint is contacted.
func TestSecretsManagerSource(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var in struct{ SecretId string }
		_ = json.Unmarshal(b, &in)
		asked = append(asked, in.SecretId)
		if r.Header.Get("X-Amz-Target") != "secretsmanager.GetSecretValue" || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDTEST/") {
			t.Errorf("request: target %q", r.Header.Get("X-Amz-Target"))
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch in.SecretId {
		case "vettid-org/staging/push/blob-keys":
			_, _ = w.Write([]byte(`{"Name":"vettid-org/staging/push/blob-keys","SecretString":"{\"current\":\"00000001\"}"}`))
		case "vettid-org/staging/push/apns":
			_, _ = w.Write([]byte(`{"Name":"x","SecretString":""}`))
		default:
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"__type":"ResourceNotFoundException","Message":"Secrets Manager can't find the specified secret."}`))
		}
	}))
	defer srv.Close()
	cfg := aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("AKIDTEST", "made-up-secret", ""),
		RetryMaxAttempts: 1}
	src := NewSecretsManager(cfg, "vettid-org/staging/push", srv.URL)
	ctx := context.Background()
	b, err := src.Get(ctx, secrets.BlobKeys)
	if err != nil || string(b) != `{"current":"00000001"}` {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := src.Get(ctx, secrets.FCM); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("missing secret: %v", err)
	}
	if _, err := src.Get(ctx, secrets.APNs); err == nil || errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("empty secret: %v", err)
	}
	if strings.Join(asked, " ") != "vettid-org/staging/push/blob-keys vettid-org/staging/push/fcm vettid-org/staging/push/apns" {
		t.Fatalf("secret ids asked: %v", asked)
	}
	creds, err := Credentials(cfg)(ctx)
	if err != nil || creds.AccessKeyID != "AKIDTEST" {
		t.Fatalf("credentials: %v", err)
	}
	if _, err := Credentials(aws.Config{})(ctx); err == nil {
		t.Fatal("credentials without a provider")
	}
}
