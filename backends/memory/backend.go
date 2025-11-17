package memory

import (
	"sync"

	"github.com/The127/signr"
)

// backend manages signing key groups and provides access to them through a thread-safe structure.
type backend struct {
	mu     sync.Mutex
	groups map[string]*keyGroup
	clock  Clock
}

// GetGroup retrieves or initializes a signing key group by its name.
// If the group does not exist, it creates a new one and adds it to the backend.
// Returns the corresponding BackendGroup and any error encountered during execution.
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
