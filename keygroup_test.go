package signr_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/The127/signr"
)

type notSealingConfig struct{}

func (notSealingConfig) Create() (signr.Backend, error) {
	return notSealingBackend{}, nil
}

type notSealingBackend struct{}

func (notSealingBackend) GetGroup(_ string, _ signr.GroupOptions) (signr.BackendGroup, error) {
	return notSealingGroup{}, nil
}

type notSealingGroup struct{}

func (notSealingGroup) GetKey(_ string) (signr.SigningKey, error) {
	return nil, errors.New("no signing keys here")
}

func (notSealingGroup) PublicKeys() ([]signr.PublicKey, error) {
	return []signr.PublicKey{}, nil
}

func TestABackendThatCannotSealIsRefusedInsteadOfHandingOutNoKey(t *testing.T) {
	// arrange
	manager, err := signr.New(signr.Config{Backend: notSealingConfig{}})
	require.NoError(t, err)
	group := manager.GetGroup("sealing")

	// act
	key, err := group.GetSealingKey()

	// assert
	assert.ErrorContains(t, err, "cannot seal")
	assert.Nil(t, key)
}
