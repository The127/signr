package memory

import (
	"crypto"
	"fmt"
	"sync"

	"github.com/The127/signr"
	"github.com/The127/signr/internal/keyinfra"
)

type keyGroup struct {
	mu      sync.Mutex
	keys    map[string]keyVersions
	clock   Clock
	sealing *keyinfra.Sealer
}

// GetKey returns the active key for the algorithm, generating one on the first call.
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

	keyStrategy, err := keyinfra.GetKeyStrategy(jwa)
	if err != nil {
		return nil, err
	}

	keyPair, err := keyStrategy.Generate(g.clock.Now())
	if err != nil {
		return nil, fmt.Errorf("generating key pair: %w", err)
	}

	signer, ok := keyPair.PrivateKey().(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("generated %s key of type %T cannot sign", jwa, keyPair.PrivateKey())
	}

	publicKey, err := keyinfra.KeepPublicKey(keyPair.PublicKey())
	if err != nil {
		return nil, err
	}

	key := &signingKey{
		kid:              keyPair.Kid(),
		algorithm:        jwa,
		hash:             keyStrategy.Hash(),
		publicKey:        publicKey,
		signer:           keyinfra.NewOpaqueSigner(publicKey, signer.Sign),
		createdTimestamp: keyPair.CreatedAt(),
		active:           true,
	}

	versions = append(versions, key)
	g.keys[jwa] = versions

	return key, nil
}

// PublicKeys returns the public half of every key version in the group, generating none.
func (g *keyGroup) PublicKeys() ([]signr.PublicKey, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	publicKeys := []signr.PublicKey{}
	for _, versions := range g.keys {
		for _, key := range versions {
			publicKeys = append(publicKeys, signr.PublicKey{
				KeyID:     key.kid,
				Algorithm: key.algorithm,
				Key:       key.publicKey.Copy(),
			})
		}
	}

	return publicKeys, nil
}
