package signr

import "fmt"

type KeyManager interface {
	GetGroup(name string, opts ...GroupOption) KeyGroup
}

func New(cfg Config) (KeyManager, error) {
	backend, err := cfg.Backend.Create()
	if err != nil {
		return nil, fmt.Errorf("failed to create backend: %w", err)
	}

	return &keyManager{backend: backend}, nil
}

type keyManager struct {
	backend Backend
}

type GroupOption func(*GroupOptions)

type GroupOptions struct {
	AutoCreate bool
}

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
