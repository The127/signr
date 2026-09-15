package directory_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAGroupNameOutsideTheSafeCharactersIsRefused(t *testing.T) {
	names := []string{
		"",
		".",
		"..",
		"../escaped",
		"a/../b",
		"./b",
		"b/",
		"Signing",
		"a b",
		strings.Repeat("a", 256),
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			// arrange
			path := t.TempDir()
			group := newGroup(t, path, name)

			// act
			_, err := group.GetKey("EdDSA")

			// assert
			assert.ErrorContains(t, err, fmt.Sprintf("group name %q", name))
			written, err := os.ReadDir(path)
			require.NoError(t, err)
			assert.Empty(t, written)
		})
	}
}

func TestAGroupNameOfSafeCharactersIsAccepted(t *testing.T) {
	names := []string{
		"signing",
		"tenant-a_0",
		strings.Repeat("a", 255),
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			// arrange
			group := newGroup(t, t.TempDir(), name)

			// act
			_, err := group.GetKey("EdDSA")

			// assert
			assert.NoError(t, err)
		})
	}
}
