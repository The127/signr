package directory_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func plantFile(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, nil, 0o600))
}

func plantDirectory(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.Mkdir(path, 0o700))
}

func plantSymlinkToTheKey(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.Symlink("EdDSA.pem", path))
}

func TestAForeignFileInAGroupFailsTheListingClosed(t *testing.T) {
	for _, name := range []string{"notes.txt", "EdDSA"} {
		t.Run(name, func(t *testing.T) {
			// arrange
			path := t.TempDir()
			group := newGroup(t, path, "signing")
			_, err := group.GetKey("EdDSA")
			require.NoError(t, err)
			plantFile(t, filepath.Join(path, "signing", name))

			// act
			_, err = group.PublicKeys()

			// assert
			assert.ErrorContains(t, err, name)
		})
	}
}

func TestAForeignDotFileInAGroupFailsTheListingClosed(t *testing.T) {
	plants := map[string]func(t *testing.T, path string){
		".notes.pem.txt": plantFile,
		".stash.pem.d":   plantDirectory,
		".EdDSA.pem.0123456789abcdef0123456789abcdef":   plantSymlinkToTheKey,
		".RS256.pem.0123456789abcdef0123456789abcdef":   plantDirectory,
		".unknown.pem.0123456789abcdef0123456789abcdef": plantFile,
		".EdDSA.pem.0123456789abcdef0123456789abcde":    plantFile,
		".EdDSA.pem.0123456789ABCDEF0123456789ABCDEF":   plantFile,
		".EdDSA.pem.txt": plantFile,
	}

	for name, plant := range plants {
		t.Run(name, func(t *testing.T) {
			// arrange
			path := t.TempDir()
			group := newGroup(t, path, "signing")
			_, err := group.GetKey("EdDSA")
			require.NoError(t, err)
			plant(t, filepath.Join(path, "signing", name))

			// act
			_, err = group.PublicKeys()

			// assert
			assert.ErrorContains(t, err, name)
		})
	}
}

func TestALeftoverTemporaryKeyFileIsNotListed(t *testing.T) {
	for _, name := range []string{
		".EdDSA.pem.0123456789abcdef0123456789abcdef",
		".AES-256-GCM.pem.0123456789abcdef0123456789abcdef",
	} {
		t.Run(name, func(t *testing.T) {
			// arrange
			path := t.TempDir()
			group := newGroup(t, path, "signing")
			key, err := group.GetKey("EdDSA")
			require.NoError(t, err)
			plantFile(t, filepath.Join(path, "signing", name))

			// act
			publicKeys, err := group.PublicKeys()

			// assert
			require.NoError(t, err)
			require.Len(t, publicKeys, 1)
			assert.Equal(t, key.KeyID(), publicKeys[0].KeyID)
		})
	}
}

func TestListingAnEmptyGroupCreatesNoDirectory(t *testing.T) {
	// arrange
	path := t.TempDir()
	group := newGroup(t, path, "signing")

	// act
	publicKeys, err := group.PublicKeys()

	// assert
	require.NoError(t, err)
	assert.Empty(t, publicKeys)
	assert.NoDirExists(t, filepath.Join(path, "signing"))
}
