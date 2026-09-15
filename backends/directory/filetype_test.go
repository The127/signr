package directory_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/The127/signr"
)

func getKeyWithin(t *testing.T, group signr.KeyGroup, timeout time.Duration) error {
	t.Helper()

	done := make(chan error, 1)
	go func() {
		_, err := group.GetKey("EdDSA")
		done <- err
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		t.Fatalf("GetKey still blocked after %s", timeout)
		return nil
	}
}

func TestAKeyFileLargerThanAnyKeyFailsClosed(t *testing.T) {
	// arrange
	path := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(path, "signing"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(path, "signing", "EdDSA.pem"), make([]byte, 1<<20), 0o600))
	group := newGroup(t, path, "signing")

	// act
	_, err := group.GetKey("EdDSA")

	// assert
	assert.ErrorContains(t, err, "larger than")
}

func TestAKeyFileThatIsAFIFOFailsClosedInsteadOfHanging(t *testing.T) {
	// arrange
	path := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(path, "signing"), 0o700))
	require.NoError(t, syscall.Mkfifo(filepath.Join(path, "signing", "EdDSA.pem"), 0o600))
	group := newGroup(t, path, "signing")

	// act
	err := getKeyWithin(t, group, 5*time.Second)

	// assert
	assert.ErrorContains(t, err, "not a regular file")
}
