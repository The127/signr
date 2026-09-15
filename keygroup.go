package signr

import "fmt"

// KeyGroup hands out the keys of one group: signing keys by algorithm, and its sealing key.
type KeyGroup interface {
	// GetKey retrieves the signing key corresponding to the specified JSON Web Algorithm (JWA).
	GetKey(jwa string) (SigningKey, error)

	// PublicKeys retrieves the public keys of every key version in the group that can still verify, in no particular order.
	PublicKeys() ([]PublicKey, error)

	// GetSealingKey returns the group's key for sealing data, or an error when the backend cannot seal.
	GetSealingKey() (SealingKey, error)
}

// errorGroup is a struct that implements the KeyGroup interface and wraps an error for operations that fail.
type errorGroup struct {
	err error
}

// GetKey retrieves a SigningKey based on the provided JWA algorithm or returns an error if one is present in the group.
func (g *errorGroup) GetKey(_ string) (SigningKey, error) {
	return nil, g.err
}

// PublicKeys retrieves the public keys of the group or returns an error if one is present in the group.
func (g *errorGroup) PublicKeys() ([]PublicKey, error) {
	return nil, g.err
}

// GetSealingKey returns the error the group was created with.
func (g *errorGroup) GetSealingKey() (SealingKey, error) {
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

// PublicKeys retrieves the public keys of the group from the backend. Returns an error if retrieval fails.
func (g *keyGroup) PublicKeys() ([]PublicKey, error) {
	publicKeys, err := g.backend.PublicKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list public keys: %w", err)
	}

	return publicKeys, nil
}

// GetSealingKey returns the backend group's sealing key, refusing a backend group that cannot seal.
func (g *keyGroup) GetSealingKey() (SealingKey, error) {
	sealing, ok := g.backend.(SealingBackendGroup)
	if !ok {
		return nil, fmt.Errorf("backend group %T cannot seal", g.backend)
	}

	key, err := sealing.GetSealingKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get sealing key: %w", err)
	}

	return key, nil
}
