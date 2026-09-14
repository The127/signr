package directory_test

import (
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func firstKeyIDsAtOnce(t *testing.T, path string, callers int) []string {
	t.Helper()

	start := make(chan struct{})
	kids := make([]string, callers)
	errs := make([]error, callers)
	waitGroup := sync.WaitGroup{}

	for index := range callers {
		group := newGroup(t, path, "signing")
		waitGroup.Go(func() {
			<-start
			key, err := group.GetKey("EdDSA")
			if err != nil {
				errs[index] = err
				return
			}
			kids[index] = key.KeyID()
		})
	}

	close(start)
	waitGroup.Wait()

	for _, err := range errs {
		require.NoError(t, err)
	}

	return kids
}

func TestConcurrentFirstCallsAgreeOnTheKeyThatSurvivesARestart(t *testing.T) {
	// arrange
	path := t.TempDir()

	// act
	kids := firstKeyIDsAtOnce(t, path, 16)

	// assert
	stored, err := newGroup(t, path, "signing").GetKey("EdDSA")
	require.NoError(t, err)
	assert.Equal(t, slices.Repeat([]string{stored.KeyID()}, 16), kids)
}
