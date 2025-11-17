package keyinfra

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"
)

type RSAKeyStrategy struct{}

func (s *RSAKeyStrategy) Generate(now time.Time) (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generating key pair: %w", err)
	}

	publicKey := privateKey.Public()
	kid, err := computeRSAPublicKeyKid(publicKey)
	if err != nil {
		return nil, fmt.Errorf("computing kid: %w", err)
	}

	return &KeyPair{
		publicKey:  publicKey,
		privateKey: privateKey,
		kid:        kid,
		createdAt:  now,
	}, nil
}

func computeRSAPublicKeyKid(pub crypto.PublicKey) (string, error) {
	// RFC 7638: JWK Thumbprint uses the public key fields only
	jwk := map[string]string{
		"e":   base64.RawURLEncoding.EncodeToString(bigIntToBytes(pub.(*rsa.PublicKey).E)),
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(pub.(*rsa.PublicKey).N.Bytes()),
	}

	b, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// bigIntToBytes encodes an int as a big-endian byte slice
func bigIntToBytes(i int) []byte {
	if i == 0 {
		return []byte{0}
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte(i & 0xff)}, b...)
		i >>= 8
	}
	return b
}

func (s *RSAKeyStrategy) Import(serializedPrivateKey string) (any, any, error) {
	block, _ := pem.Decode([]byte(serializedPrivateKey))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, nil, fmt.Errorf("failed to decode PEM block containing RSA private key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing PKCS1 private key: %w", err)
	}

	return key, &key.PublicKey, nil
}

func (s *RSAKeyStrategy) Export(privateKey any) (string, error) {
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("invalid private key type, expected *rsa.PrivateKey got %T", privateKey)
	}

	der := x509.MarshalPKCS1PrivateKey(rsaPrivateKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}
