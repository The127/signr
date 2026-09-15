package directory_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/The127/signr"
	"github.com/The127/signr/backends/directory"
)

func newGroup(t *testing.T, path string, name string) signr.KeyGroup {
	t.Helper()

	manager, err := signr.New(signr.Config{Backend: directory.Config{Path: path}})
	require.NoError(t, err)

	return manager.GetGroup(name)
}

func TestAKeySurvivesARestart(t *testing.T) {
	// arrange
	path := t.TempDir()
	key, err := newGroup(t, path, "signing").GetKey("EdDSA")
	require.NoError(t, err)

	// act
	again, err := newGroup(t, path, "signing").GetKey("EdDSA")

	// assert
	require.NoError(t, err)
	assert.Equal(t, key.KeyID(), again.KeyID())
}

func TestAnRSAKeySurvivesARestartAndStillSignsWhatTheStandardLibraryVerifies(t *testing.T) {
	// arrange
	path := t.TempDir()
	key, err := newGroup(t, path, "signing").GetKey("RS256")
	require.NoError(t, err)
	message := []byte("hello")
	digest := sha256.Sum256(message)

	// act
	again, err := newGroup(t, path, "signing").GetKey("RS256")

	// assert
	require.NoError(t, err)
	assert.Equal(t, key.KeyID(), again.KeyID())
	signature, err := again.Sign(message)
	require.NoError(t, err)
	publicKey, err := again.PublicKey()
	require.NoError(t, err)
	assert.NoError(t, rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], signature))
}
