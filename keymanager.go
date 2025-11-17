package signr

import "fmt"

// KeyManager defines an interface for managing cryptographic key groups used in signing and verification operations.
// GetGroup provides access to a KeyGroup by name, allowing optional configurations through GroupOptions parameters.
type KeyManager interface {

	// GetGroup retrieves a KeyGroup by its name, with optional configurations applied through variadic GroupOption parameters.
	GetGroup(name string, opts ...GroupOption) KeyGroup
}

// New initializes and returns a KeyManager instance configured with the provided backend, or an error if creation fails.
func New(cfg Config) (KeyManager, error) {
	backend, err := cfg.Backend.Create()
	if err != nil {
		return nil, fmt.Errorf("failed to create backend: %w", err)
	}

	return &keyManager{backend: backend}, nil
}

// keyManager is a struct that implements the KeyManager interface for managing cryptographic key groups.
// It utilizes a Backend to handle key storage and retrieval for cryptographic operations.
type keyManager struct {
	backend Backend
}

// GroupOption defines a function type used to configure GroupOptions for customizing group behaviors.
type GroupOption func(*GroupOptions)

// GroupOptions provides configuration options for managing groups, such as enabling automatic creation of missing groups.
type GroupOptions struct {
}

// GetGroup retrieves a KeyGroup by its name with optional customization via GroupOptions. Returns an errorGroup on failure.
func (k *keyManager) GetGroup(name string, opts ...GroupOption) KeyGroup {
	var groupOpts GroupOptions
	for _, opt := range opts {
		opt(&groupOpts)
	}

	backendGroup, err := k.backend.GetGroup(name, groupOpts)
	if err != nil {
		return &errorGroup{err: err}
	}

	return &keyGroup{
		backend: backendGroup,
		opts:    groupOpts,
	}
}
