package directory_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/The127/signr"
	"github.com/The127/signr/backends/directory"
)

func TestAKeyDirectoryThatIsNoDirectoryIsRefusedAtCreate(t *testing.T) {
	// arrange
	parent := t.TempDir()
	file := filepath.Join(parent, "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))

	paths := map[string]string{
		"missing": filepath.Join(parent, "missing"),
		"file":    file,
	}

	for name, path := range paths {
		t.Run(name, func(t *testing.T) {
			// act
			_, err := signr.New(signr.Config{Backend: directory.Config{Path: path}})

			// assert
			assert.Error(t, err)
		})
	}
}

func TestAKeyDirectoryOthersCanWriteIsRefusedAtCreate(t *testing.T) {
	for _, mode := range []os.FileMode{0o720, 0o702, 0o777} {
		t.Run(fmt.Sprintf("%#o", mode), func(t *testing.T) {
			// arrange
			path := t.TempDir()
			require.NoError(t, os.Chmod(path, mode))

			// act
			_, err := signr.New(signr.Config{Backend: directory.Config{Path: path}})

			// assert
			assert.ErrorContains(t, err, fmt.Sprintf("%#o", mode))
		})
	}
}

func TestAKeyDirectoryOpenedToOthersAfterCreateFailsClosed(t *testing.T) {
	// arrange
	path := t.TempDir()
	manager, err := signr.New(signr.Config{Backend: directory.Config{Path: path}})
	require.NoError(t, err)
	require.NoError(t, os.Chmod(path, 0o777))

	// act
	_, err = manager.GetGroup("signing").GetKey("EdDSA")

	// assert
	assert.ErrorContains(t, err, "0777")
}

func TestAGroupDirectoryOthersCanWriteFailsClosed(t *testing.T) {
	for _, mode := range []os.FileMode{0o720, 0o702, 0o777} {
		t.Run(fmt.Sprintf("%#o", mode), func(t *testing.T) {
			// arrange
			path := t.TempDir()
			require.NoError(t, os.Mkdir(filepath.Join(path, "signing"), 0o700))
			require.NoError(t, os.Chmod(filepath.Join(path, "signing"), mode))
			group := newGroup(t, path, "signing")

			// act
			_, err := group.GetKey("EdDSA")

			// assert
			assert.ErrorContains(t, err, fmt.Sprintf("%#o", mode))
		})
	}
}

func TestDirectoriesOthersCanOnlyReadAreAccepted(t *testing.T) {
	// arrange
	path := t.TempDir()
	require.NoError(t, os.Chmod(path, 0o755))
	require.NoError(t, os.Mkdir(filepath.Join(path, "signing"), 0o700))
	require.NoError(t, os.Chmod(filepath.Join(path, "signing"), 0o755))
	group := newGroup(t, path, "signing")

	// act
	_, err := group.GetKey("EdDSA")

	// assert
	assert.NoError(t, err)
}

func TestARelativeKeyDirectoryIsRefusedAtCreate(t *testing.T) {
	for _, path := range []string{"", "keys", "./keys", "../keys"} {
		t.Run(path, func(t *testing.T) {
			// act
			_, err := signr.New(signr.Config{Backend: directory.Config{Path: path}})

			// assert
			assert.ErrorContains(t, err, "absolute")
		})
	}
}
