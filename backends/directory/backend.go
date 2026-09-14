package directory

import (
	"github.com/The127/signr"
)

type backend struct {
	path string
}

// GetGroup answers the group whose keys live in the directory named after it, refusing a name outside [a-z0-9_-]
// or longer than 255 characters.
func (backend *backend) GetGroup(name string, _ signr.GroupOptions) (signr.BackendGroup, error) {
	err := checkGroupName(name)
	if err != nil {
		return nil, err
	}

	return &keyGroup{
		directory: backend.path,
		name:      name,
	}, nil
}
