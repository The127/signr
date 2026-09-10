package memory_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnRSAKeySignsWhatTheStandardLibraryVerifies(t *testing.T) {
	// arrange
	key := newKey(t, "RS256")
	message := []byte("hello")
	digest := sha256.Sum256(message)

	// act
	signature, err := key.Sign(message)

	// assert
	require.NoError(t, err)
	publicKey, err := key.PublicKey()
	require.NoError(t, err)
	assert.NoError(t, rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], signature))
}

func TestAnRSAKeyVerifiesItsOwnSignature(t *testing.T) {
	for _, algorithm := range []string{"RS256", "RS384", "RS512"} {
		t.Run(algorithm, func(t *testing.T) {
			// arrange
			key := newKey(t, algorithm)
			message := []byte("hello")
			signature, err := key.Sign(message)
			require.NoError(t, err)

			// act
			err = key.Verify(message, signature)

			// assert
			assert.NoError(t, err)
		})
	}
}

func TestASignerSignsADigestTheStandardLibraryVerifies(t *testing.T) {
	// arrange
	key := newKey(t, "RS256")
	digest := sha256.Sum256([]byte("hello"))
	signer, err := key.Signer()
	require.NoError(t, err)

	// act
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)

	// assert
	require.NoError(t, err)
	assert.NoError(t, rsa.VerifyPKCS1v15(signer.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], signature))
}
