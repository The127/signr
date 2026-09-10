package memory_test

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/The127/signr"
	"github.com/The127/signr/backends/memory"
)

type fixedClock struct{}

func (fixedClock) Now() time.Time {
	return time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
}

func newKey(t *testing.T, algorithm string) signr.SigningKey {
	t.Helper()

	manager, err := signr.New(signr.Config{Backend: memory.Config{Clock: fixedClock{}}})
	require.NoError(t, err)

	key, err := manager.GetGroup("signing").GetKey(algorithm)
	require.NoError(t, err)

	return key
}

func TestAnUnknownAlgorithmIsRefusedInsteadOfPanicking(t *testing.T) {
	// arrange
	manager, err := signr.New(signr.Config{Backend: memory.Config{Clock: fixedClock{}}})
	require.NoError(t, err)

	// act
	_, err = manager.GetGroup("signing").GetKey("ES256")

	// assert
	assert.ErrorContains(t, err, "ES256")
}

func TestAnEdDSAKeySignsWhatTheStandardLibraryVerifies(t *testing.T) {
	// arrange
	key := newKey(t, "EdDSA")
	message := []byte("hello")

	// act
	signature, err := key.Sign(message)

	// assert
	require.NoError(t, err)
	publicKey, err := key.PublicKey()
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(publicKey.(ed25519.PublicKey), message, signature))
}

func TestAnEdDSAKeyVerifiesItsOwnSignature(t *testing.T) {
	// arrange
	key := newKey(t, "EdDSA")
	message := []byte("hello")
	signature, err := key.Sign(message)
	require.NoError(t, err)

	// act
	err = key.Verify(message, signature)

	// assert
	assert.NoError(t, err)
}

func TestAKeyRefusesASignatureOverAnotherMessage(t *testing.T) {
	// arrange
	key := newKey(t, "EdDSA")
	signature, err := key.Sign([]byte("hello"))
	require.NoError(t, err)

	// act
	err = key.Verify([]byte("goodbye"), signature)

	// assert
	assert.Error(t, err)
}

func TestASignerHoldsTheKeysPublicKey(t *testing.T) {
	// arrange
	key := newKey(t, "EdDSA")
	publicKey, err := key.PublicKey()
	require.NoError(t, err)

	// act
	signer, err := key.Signer()

	// assert
	require.NoError(t, err)
	assert.Equal(t, publicKey, signer.Public())
}
