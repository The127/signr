package directory_test

import (
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/The127/signr"
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

func listingErrorsWhileGenerating(t *testing.T, rounds int) []error {
	t.Helper()

	listingErrors := []error{}
	for range rounds {
		path := t.TempDir()
		lister := newGroup(t, path, "signing")
		generators := make([]signr.KeyGroup, 6)
		for index := range generators {
			generators[index] = newGroup(t, path, "signing")
		}

		done := make(chan struct{})
		waitGroup := sync.WaitGroup{}
		for _, generator := range generators {
			waitGroup.Go(func() {
				_, err := generator.GetKey("EdDSA")
				assert.NoError(t, err)
			})
		}
		go func() {
			waitGroup.Wait()
			close(done)
		}()

		finished := false
		for !finished {
			_, err := lister.PublicKeys()
			if err != nil {
				listingErrors = append(listingErrors, err)
			}

			select {
			case <-done:
				finished = true
			default:
			}
		}
	}

	return listingErrors
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

func TestListingWhileKeysAreGeneratedNeverFails(t *testing.T) {
	// act
	listingErrors := listingErrorsWhileGenerating(t, 200)

	// assert
	assert.Empty(t, listingErrors)
}
