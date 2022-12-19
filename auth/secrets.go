package auth

import (
	"encoding/hex"
	"errors"
	"time"
)

type Secret struct {
	Value     string
	ExpiresAt time.Time
}

func FindSecret(secretEnvVar, expirationEnvVar, defaultSecret, defaultExpiration string) (*Secret, error) {
	secretValue := getenv(secretEnvVar, defaultSecret)
	if secretValue == "" {
		return nil, errors.New(secretNotSetErrorMessage)
	}

	expiration, err := time.ParseDuration(getenv(expirationEnvVar, defaultExpiration))
	if err != nil {
		return nil, err
	}
	if expiration < 0 {
		return nil, errors.New(negativeExpirationErrorMessage)
	}

	secretBits, err := hex.DecodeString(secretValue)
	if err != nil {
		return nil, err
	}

	return &Secret{
		Value:     string(secretBits),
		ExpiresAt: time.Now().Add(expiration),
	}, nil
}
