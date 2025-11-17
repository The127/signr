package memory

import (
	"sync"
	"time"

	"github.com/The127/signr"
)

type Clock interface {
	Now() time.Time
}

type Config struct {
	Clock Clock
}

func (c Config) Create() (signr.Backend, error) {
	return &backend{
		mu:     sync.Mutex{},
		groups: map[string]*keyGroup{},
		clock:  c.Clock,
	}, nil
}
