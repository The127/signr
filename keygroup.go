package signr

import "fmt"

// KeyGroup defines an interface for retrieving signing keys based on a specified JSON Web Algorithm (JWA).
type KeyGroup interface {

	// GetKey retrieves the signing key corresponding to the specified JSON Web Algorithm (JWA).
	GetKey(jwa string) (SigningKey, error)
}

// errorGroup is a struct that implements the KeyGroup interface and wraps an error for operations that fail.
type errorGroup struct {
	err error
}

// GetKey retrieves a SigningKey based on the provided JWA algorithm or returns an error if one is present in the group.
func (g *errorGroup) GetKey(jwa string) (SigningKey, error) {
	return nil, g.err
}

// keyGroup represents a group of signing keys managed by a specific backend with customizable options.
// It implements the KeyGroup interface and provides methods for key management and retrieval.
// The backend field specifies the underlying key storage, while opts defines optional behaviors for the group.
type keyGroup struct {
	backend BackendGroup
	opts    GroupOptions
}

// GetKey retrieves the signing key for the specified JWA algorithm from the backend. Returns an error if retrieval fails.
func (g *keyGroup) GetKey(jwa string) (SigningKey, error) {
	key, err := g.backend.GetKey(jwa)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	return key, nil
}
