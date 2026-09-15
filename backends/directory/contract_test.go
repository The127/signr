package directory_test

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/The127/signr/backends/directory"
	"github.com/The127/signr/backendtest"
)

type contract struct {
	backendtest.Suite
}

func (s *contract) SetupTest() {
	s.Backend = directory.Config{Path: s.T().TempDir()}
}

func (s *contract) SetupSubTest() {
	s.Backend = directory.Config{Path: s.T().TempDir()}
}

func TestContract(t *testing.T) {
	suite.Run(t, &contract{})
}
