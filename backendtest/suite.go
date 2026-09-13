package backendtest

import (
	"github.com/stretchr/testify/suite"

	"github.com/The127/signr"
)

// Suite runs the backend contract against the backend the config creates.
type Suite struct {
	suite.Suite
	Backend signr.BackendConfig
}

func (s *Suite) newManager() signr.KeyManager {
	manager, err := signr.New(signr.Config{Backend: s.Backend})
	s.Require().NoError(err)

	return manager
}

func (s *Suite) newKey(algorithm string) signr.SigningKey {
	key, err := s.newManager().GetGroup("signing").GetKey(algorithm)
	s.Require().NoError(err)

	return key
}
