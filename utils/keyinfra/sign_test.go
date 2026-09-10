package keyinfra_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/The127/signr/utils/keyinfra"
)

func TestSignRefusesAHashForEd25519(t *testing.T) {
	// arrange
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// act
	_, err = keyinfra.Sign(key, crypto.SHA512, []byte("hello"))

	// assert
	assert.ErrorContains(t, err, "ed25519")
}

func TestVerifyRefusesAHashForEd25519(t *testing.T) {
	// arrange
	publicKey, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signature := ed25519.Sign(key, []byte("hello"))

	// act
	err = keyinfra.Verify(publicKey, crypto.SHA512, []byte("hello"), signature)

	// assert
	assert.ErrorContains(t, err, "ed25519")
}

func TestSignRefusesAnUnavailableHashInsteadOfPanicking(t *testing.T) {
	// arrange
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// act
	_, err = keyinfra.Sign(key, crypto.MD5SHA1, []byte("hello"))

	// assert
	assert.ErrorContains(t, err, "hash")
}

func TestVerifyRefusesAnUnavailableHashInsteadOfPanicking(t *testing.T) {
	// arrange
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// act
	err = keyinfra.Verify(key.Public(), crypto.MD5SHA1, []byte("hello"), []byte("signature"))

	// assert
	assert.ErrorContains(t, err, "hash")
}
