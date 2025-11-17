package memory

import (
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

// Create initializes and returns a new instance of signr.Backend with default configuration values.
func (c Config) Create() (signr.Backend, error) {
	return &backend{
		mu:     sync.Mutex{},
		groups: map[string]*keyGroup{},
		clock:  c.Clock,
	}, nil
}
