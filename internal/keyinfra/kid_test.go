package keyinfra_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/The127/signr/internal/keyinfra"
)

func TestKeyIDRefusesAnUnsupportedKeyTypeInsteadOfPanicking(t *testing.T) {
	// arrange
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// act
	_, err = keyinfra.KeyID(key.Public())

	// assert
	assert.ErrorContains(t, err, "ecdsa")
}
