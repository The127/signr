package signr

import "fmt"

type KeyGroup interface {
	GetKey(jwa string) (SigningKey, error)
}

type errorGroup struct {
	err error
}

func (g *errorGroup) GetKey(jwa string) (SigningKey, error) {
	return nil, g.err
}

type keyGroup struct {
	backend BackendGroup
	opts    GroupOptions
}

func (g *keyGroup) GetKey(jwa string) (SigningKey, error) {
	key, err := g.backend.GetKey(jwa)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	return key, nil
}
