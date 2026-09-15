package memory_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/The127/signr/backends/memory"
	"github.com/The127/signr/backendtest"
)

type fixedClock struct{}

func (fixedClock) Now() time.Time {
	return time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
}

func TestContract(t *testing.T) {
	suite.Run(t, &backendtest.Suite{Backend: memory.Config{Clock: fixedClock{}}})
}

func TestSealingContract(t *testing.T) {
	suite.Run(t, &backendtest.SealingSuite{Backend: memory.Config{Clock: fixedClock{}}})
}
