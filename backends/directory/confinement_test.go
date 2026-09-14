package directory_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAGroupDirectoryLinkedOutsideFailsClosed(t *testing.T) {
	// arrange
	parent := t.TempDir()
	path := filepath.Join(parent, "keys")
	outside := filepath.Join(parent, "outside")
	require.NoError(t, os.Mkdir(path, 0o700))
	require.NoError(t, os.Mkdir(outside, 0o700))
	require.NoError(t, os.Symlink(outside, filepath.Join(path, "signing")))
	group := newGroup(t, path, "signing")

	// act
	_, err := group.GetKey("EdDSA")

	// assert
	assert.Error(t, err)
	written, err := os.ReadDir(outside)
	require.NoError(t, err)
	assert.Empty(t, written)
}

func TestAKeyFileThatIsASymlinkFailsClosed(t *testing.T) {
	// arrange
	path := t.TempDir()
	_, err := newGroup(t, path, "signing").GetKey("EdDSA")
	require.NoError(t, err)
	groupPath := filepath.Join(path, "signing")
	require.NoError(t, os.Rename(filepath.Join(groupPath, "EdDSA.pem"), filepath.Join(groupPath, "stash.pem")))
	require.NoError(t, os.Symlink("stash.pem", filepath.Join(groupPath, "EdDSA.pem")))
	group := newGroup(t, path, "signing")

	// act
	_, err = group.GetKey("EdDSA")

	// assert
	assert.ErrorContains(t, err, "not a regular file")
}

func TestAGroupDirectoryLinkedToAnotherGroupFailsClosed(t *testing.T) {
	// arrange
	path := t.TempDir()
	_, err := newGroup(t, path, "a").GetKey("EdDSA")
	require.NoError(t, err)
	require.NoError(t, os.Symlink("a", filepath.Join(path, "b")))
	group := newGroup(t, path, "b")

	// act
	_, err = group.GetKey("EdDSA")

	// assert
	assert.ErrorContains(t, err, "not a directory")
}
