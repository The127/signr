package keyinfra

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"
)

type EdDSAKeyStrategy struct{}

func (s *EdDSAKeyStrategy) Generate(now time.Time) (*KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key pair: %w", err)
	}

	kid := computeEdCSAPublicKeyKid(publicKey)

	return &KeyPair{
		publicKey:  publicKey,
		privateKey: privateKey,
		kid:        kid,
		createdAt:  now,
	}, nil
}

func computeEdCSAPublicKeyKid(key ed25519.PublicKey) string {
	hash := sha256.Sum256(key)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func (s *EdDSAKeyStrategy) Export(privateKey any) (string, error) {
	ed25519PrivateKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return "", fmt.Errorf("invalid private key type, expected ed25519.PrivateKey got %T", privateKey)
	}

	der, err := x509.MarshalPKCS8PrivateKey(ed25519PrivateKey)
	if err != nil {
		return "", fmt.Errorf("marshalling private key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

func (s *EdDSAKeyStrategy) Import(serializedPrivateKey string) (any, any, error) {
	block, _ := pem.Decode([]byte(serializedPrivateKey))
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing PKCS8 private key: %w", err)
	}

	ed25519PrivateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("not an Ed25519 private key")
	}

	publicKey := ed25519PrivateKey.Public().(ed25519.PublicKey)
	return ed25519PrivateKey, publicKey, nil
}
