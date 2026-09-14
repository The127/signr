package keyinfra_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/The127/signr/internal/keyinfra"
)

func TestKeepingAnUnsupportedPublicKeyTypeFailsClosed(t *testing.T) {
	// arrange
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// act
	_, err = keyinfra.KeepPublicKey(key.Public())

	// assert
	assert.ErrorContains(t, err, "ecdsa")
}

func TestKeepingAnIncompleteRSAKeyFailsClosedInsteadOfPanicking(t *testing.T) {
	keys := map[string]crypto.PublicKey{
		"nil key":    (*rsa.PublicKey)(nil),
		"no modulus": &rsa.PublicKey{},
	}

	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			// act
			_, err := keyinfra.KeepPublicKey(key)

			// assert
			assert.Error(t, err)
		})
	}
}

func TestRewritingAnEd25519KeyAfterKeepingItLeavesTheKeptKeyUnchanged(t *testing.T) {
	// arrange
	original, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	want := slices.Clone(original)
	kept, err := keyinfra.KeepPublicKey(original)
	require.NoError(t, err)
	copy(original, make([]byte, ed25519.PublicKeySize))
	copy(kept.Copy().(ed25519.PublicKey), make([]byte, ed25519.PublicKeySize))

	// act
	handedOut := kept.Copy()

	// assert
	assert.Equal(t, want, handedOut)
}

func TestRewritingAnRSAKeyAfterKeepingItLeavesTheKeptKeyUnchanged(t *testing.T) {
	// arrange
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	want := &rsa.PublicKey{
		N: new(big.Int).Set(private.N),
		E: private.E,
	}
	kept, err := keyinfra.KeepPublicKey(&private.PublicKey)
	require.NoError(t, err)
	private.N.SetInt64(1)
	kept.Copy().(*rsa.PublicKey).N.SetInt64(2)

	// act
	handedOut := kept.Copy()

	// assert
	assert.Equal(t, want, handedOut)
}
