package memory_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/The127/signr/backends/memory"
)

func TestCreateRefusesAConfigWithoutClockInsteadOfPanicking(t *testing.T) {
	// arrange
	config := memory.Config{}

	// act
	_, err := config.Create()

	// assert
	assert.ErrorContains(t, err, "clock")
}
