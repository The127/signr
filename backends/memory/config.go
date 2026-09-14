package memory

import (
	"errors"
	"sync"
	"time"

	"github.com/The127/signr"
)

// Clock defines an interface for getting the current time.
type Clock interface {
	Now() time.Time
}

// Config contains configuration settings, including a Clock used to retrieve the current time.
type Config struct {
	Clock Clock
}

// Create returns an empty in-memory backend, refusing a config without a clock.
func (c Config) Create() (signr.Backend, error) {
	if c.Clock == nil {
		return nil, errors.New("memory backend needs a clock")
	}

	return &backend{
		mu:     sync.Mutex{},
		groups: map[string]*keyGroup{},
		clock:  c.Clock,
	}, nil
}
