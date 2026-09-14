package openbao

import (
	"fmt"
	"regexp"

	"github.com/The127/signr"
)

var plainKeyName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

type backend struct {
	transit transit
}

// GetGroup returns the group whose keys are the Transit keys named after it, refusing a name that is not a plain
// key name.
func (backend *backend) GetGroup(name string, _ signr.GroupOptions) (signr.BackendGroup, error) {
	if !plainKeyName.MatchString(name) {
		return nil, fmt.Errorf("group name %q is not a plain transit key name", name)
	}

	return &keyGroup{
		name:    name,
		transit: backend.transit,
	}, nil
}
