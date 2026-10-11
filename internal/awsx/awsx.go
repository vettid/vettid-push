// Package awsx is the gateway's use of AWS: reading its secrets from
// Secrets Manager at start (PUSH-GATEWAY §10.2) and handing its task-role
// credentials to the FCM workload identity federation (§10.3).
//
// The secrets are encrypted under the gateway's KMS key; Secrets Manager
// decrypts them for the task role, so they exist in plaintext only in
// this process's memory.
package awsx

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/vettid/vettid-push/internal/secrets"
)

// Load returns the SDK configuration from the standard chain (the ECS
// task role in production) for region.
func Load(ctx context.Context, region string) (aws.Config, error) {
	return awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
}

// Credentials returns a function yielding cfg's current credentials (the
// SDK caches and renews them).
func Credentials(cfg aws.Config) func(context.Context) (aws.Credentials, error) {
	return func(ctx context.Context) (aws.Credentials, error) {
		if cfg.Credentials == nil {
			return aws.Credentials{}, errors.New("awsx: no credentials provider")
		}
		return cfg.Credentials.Retrieve(ctx)
	}
}

// SecretsManager reads the secrets <Prefix>/<name>.
type SecretsManager struct {
	Client *secretsmanager.Client
	// Prefix is vettid-org/<stage>/push.
	Prefix string
}

// NewSecretsManager returns the Secrets Manager source for cfg. endpoint,
// if set, replaces the service endpoint (tests).
func NewSecretsManager(cfg aws.Config, prefix, endpoint string) *SecretsManager {
	return &SecretsManager{Prefix: prefix, Client: secretsmanager.NewFromConfig(cfg, func(o *secretsmanager.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
	})}
}

// Get implements secrets.Source. Errors name the secret, never its
// content.
func (s *SecretsManager) Get(ctx context.Context, name string) ([]byte, error) {
	id := s.Prefix + "/" + name
	out, err := s.Client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(id)})
	var nf *smtypes.ResourceNotFoundException
	switch {
	case errors.As(err, &nf):
		return nil, secrets.ErrNotFound
	case err != nil:
		return nil, fmt.Errorf("awsx: reading secret %s: %w", id, err)
	}
	var b []byte
	if out.SecretString != nil {
		b = []byte(*out.SecretString)
	} else {
		b = out.SecretBinary
	}
	if len(b) == 0 || len(b) > secrets.MaxSize {
		return nil, fmt.Errorf("awsx: secret %s is empty or too large", id)
	}
	return b, nil
}
