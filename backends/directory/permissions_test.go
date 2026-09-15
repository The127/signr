package directory_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestARefusedKeyFileNamesItsGroup(t *testing.T) {
	// arrange
	path := t.TempDir()
	_, err := newGroup(t, path, "tenant-a").GetKey("EdDSA")
	require.NoError(t, err)
	require.NoError(t, os.Chmod(filepath.Join(path, "tenant-a", "EdDSA.pem"), 0o640))
	group := newGroup(t, path, "tenant-a")

	// act
	_, err = group.GetKey("EdDSA")

	// assert
	assert.ErrorContains(t, err, "tenant-a")
}

func TestAKeyFileOpenToGroupOrOthersFailsClosed(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o620, 0o610, 0o604, 0o602, 0o601} {
		t.Run(fmt.Sprintf("%#o", mode), func(t *testing.T) {
			// arrange
			path := t.TempDir()
			_, err := newGroup(t, path, "signing").GetKey("EdDSA")
			require.NoError(t, err)
			require.NoError(t, os.Chmod(filepath.Join(path, "signing", "EdDSA.pem"), mode))

			// act
			_, err = newGroup(t, path, "signing").GetKey("EdDSA")

			// assert
			assert.ErrorContains(t, err, fmt.Sprintf("%#o", mode))
		})
	}
}

func TestASealingKeyFileOpenToGroupOrOthersFailsTheListingClosed(t *testing.T) {
	// arrange
	path := t.TempDir()
	group := newGroup(t, path, "signing")
	_, err := group.GetSealingKey("AES-256-GCM")
	require.NoError(t, err)
	require.NoError(t, os.Chmod(filepath.Join(path, "signing", "AES-256-GCM.pem"), 0o640))

	// act
	_, err = group.PublicKeys()

	// assert
	assert.ErrorContains(t, err, "0640")
}
