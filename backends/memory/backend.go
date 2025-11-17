package memory

import (
	"sync"

	"github.com/The127/signr"
)

type backend struct {
	mu     sync.Mutex
	groups map[string]*keyGroup
	clock  Clock
}

func (b *backend) GetGroup(name string, opts signr.GroupOptions) (signr.BackendGroup, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	group, ok := b.groups[name]
	if !ok {
		group = &keyGroup{
			mu:    sync.Mutex{},
			keys:  map[string]keyVersions{},
			clock: b.clock,
		}
		b.groups[name] = group
	}

	return group, nil
}
