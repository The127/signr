package memory_test

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 7638: SHA-256 over the required public members in lexicographic order, no whitespace.
func thumbprint(json string) string {
	digest := sha256.Sum256([]byte(json))

	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func TestAnEdDSAKeyIdIsItsJWKThumbprint(t *testing.T) {
	// arrange
	key := newKey(t, "EdDSA")
	publicKey, err := key.PublicKey()
	require.NoError(t, err)
	x := base64.RawURLEncoding.EncodeToString(publicKey.(ed25519.PublicKey))

	// act
	kid := key.KeyID()

	// assert
	assert.Equal(t, thumbprint(`{"crv":"Ed25519","kty":"OKP","x":"`+x+`"}`), kid)
}

func TestAnRSAKeyIdIsItsJWKThumbprint(t *testing.T) {
	// arrange
	key := newKey(t, "RS256")
	publicKey, err := key.PublicKey()
	require.NoError(t, err)
	rsaKey := publicKey.(*rsa.PublicKey)
	e := base64.RawURLEncoding.EncodeToString([]byte{byte(rsaKey.E >> 16), byte(rsaKey.E >> 8), byte(rsaKey.E)})
	n := base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes())

	// act
	kid := key.KeyID()

	// assert
	assert.Equal(t, thumbprint(`{"e":"`+e+`","kty":"RSA","n":"`+n+`"}`), kid)
}
