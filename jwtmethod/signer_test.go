package jwtmethod_test

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/The127/signr"
	"github.com/The127/signr/backends/memory"
	"github.com/The127/signr/jwtmethod"
)

type fixedClock struct{}

func (fixedClock) Now() time.Time {
	return time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
}

func newKey(t *testing.T, algorithm string) signr.SigningKey {
	t.Helper()

	manager, err := signr.New(signr.Config{Backend: memory.Config{Clock: fixedClock{}}})
	require.NoError(t, err)

	key, err := manager.GetGroup("tokens").GetKey(algorithm)
	require.NoError(t, err)

	return key
}

func TestATokenSignedWithTheMethodVerifiesWithThePublicKey(t *testing.T) {
	// arrange
	key := newKey(t, "EdDSA")
	publicKey, err := key.PublicKey()
	require.NoError(t, err)
	token := jwt.NewWithClaims(jwtmethod.NewJwtSigningMethod(key), jwt.MapClaims{"sub": "alice"})

	// act
	signed, err := token.SignedString(nil)

	// assert
	require.NoError(t, err)
	parsed, err := jwt.Parse(signed, func(*jwt.Token) (any, error) {
		return publicKey.(ed25519.PublicKey), nil
	})
	require.NoError(t, err)
	assert.True(t, parsed.Valid)
}

func TestTheMethodRefusesToVerifyInsteadOfPanicking(t *testing.T) {
	// arrange
	method := jwtmethod.NewJwtSigningMethod(newKey(t, "EdDSA"))

	// act
	err := method.Verify("header.payload", []byte("signature"), nil)

	// assert
	assert.ErrorContains(t, err, "public key")
}
