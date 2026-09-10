package memory

import (
	"crypto"
	"fmt"
	"sync"

	"github.com/The127/signr"
	"github.com/The127/signr/internal/keyinfra"
)

// keyGroup manages signing keys grouped by JWA algorithm name.
// It is safe for concurrent use.
type keyGroup struct {
	mu    sync.Mutex
	keys  map[string]keyVersions
	clock Clock
}

// GetKey returns the currently active signing key for the given JWA algorithm.
//
// If there is no active key yet, GetKey generates a new key pair using the
// configured key strategy and the group's Clock, stores it as the active
// version for the algorithm, and returns it.
//
// The returned SigningKey can be used for signing and verification
// operations according to the specified algorithm.
//
// Possible errors include failures in key generation or key strategy lookup.
func (g *keyGroup) GetKey(jwa string) (signr.SigningKey, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	versions := g.keys[jwa]
	if versions == nil {
		versions = keyVersions{}
		g.keys[jwa] = versions
	}

	for _, key := range versions {
		if key.active {
			return key, nil
		}
	}

	keyStrategy := keyinfra.GetKeyStrategy(jwa)
	keyPair, err := keyStrategy.Generate(g.clock.Now())
	if err != nil {
		return nil, fmt.Errorf("generating key pair: %w", err)
	}

	signer, ok := keyPair.PrivateKey().(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("generated %s key of type %T cannot sign", jwa, keyPair.PrivateKey())
	}

	key := &signingKey{
		kid:              keyPair.Kid(),
		algorithm:        jwa,
		publicKey:        keyPair.PublicKey(),
		signer:           signer,
		createdTimestamp: keyPair.CreatedAt(),
		active:           true,
	}

	versions = append(versions, key)
	g.keys[jwa] = versions

	return key, nil
}
