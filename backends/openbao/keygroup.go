package openbao

import (
	"fmt"
	"strconv"

	"github.com/The127/signr"
	"github.com/The127/signr/internal/keyinfra"
)

var transitKeyTypes = map[string]string{
	"EdDSA": "ed25519",
	"RS256": "rsa-4096",
	"RS384": "rsa-4096",
	"RS512": "rsa-4096",
}

type keyGroup struct {
	name    string
	transit transit
}

// GetKey returns the latest version of the group's key for the algorithm, creating the key in Transit on the first
// call.
func (group *keyGroup) GetKey(jwa string) (signr.SigningKey, error) {
	strategy, err := keyinfra.GetKeyStrategy(jwa)
	if err != nil {
		return nil, err
	}

	keyType, found := transitKeyTypes[jwa]
	if !found {
		return nil, fmt.Errorf("no transit key type for algorithm %q", jwa)
	}

	name := keyName(group.name, jwa)

	key, err := group.transit.createKey(name, keyType)
	if err != nil {
		return nil, err
	}

	publicKey, err := key.publicKey(keyType, key.LatestVersion)
	if err != nil {
		return nil, fmt.Errorf("transit key %s: %w", name, err)
	}

	kid, err := keyinfra.KeyID(publicKey)
	if err != nil {
		return nil, fmt.Errorf("transit key %s: %w", name, err)
	}

	return signingKey{
		kid:       kid,
		algorithm: jwa,
		hash:      strategy.Hash(),
		signer: transitSigner{
			transit: group.transit,
			name:    name,
			version: key.LatestVersion,
			public:  publicKey,
		},
	}, nil
}

// PublicKeys returns the public half of every version of the group's keys that Transit still verifies with, creating
// none.
func (group *keyGroup) PublicKeys() ([]signr.PublicKey, error) {
	publicKeys := []signr.PublicKey{}

	for jwa, keyType := range transitKeyTypes {
		name := keyName(group.name, jwa)

		key, found, err := group.transit.readKey(name)
		if err != nil {
			return nil, err
		}

		if !found {
			continue
		}

		for versionName := range key.Keys {
			version, err := strconv.Atoi(versionName)
			if err != nil {
				return nil, fmt.Errorf("transit key %s has a version named %q: %w", name, versionName, err)
			}

			if version < key.MinDecryptionVersion {
				continue
			}

			publicKey, err := key.publicKey(keyType, version)
			if err != nil {
				return nil, fmt.Errorf("transit key %s: %w", name, err)
			}

			kid, err := keyinfra.KeyID(publicKey)
			if err != nil {
				return nil, fmt.Errorf("transit key %s: %w", name, err)
			}

			publicKeys = append(publicKeys, signr.PublicKey{
				KeyID:     kid,
				Algorithm: jwa,
				Key:       publicKey,
			})
		}
	}

	return publicKeys, nil
}

func keyName(group string, jwa string) string {
	return group + "-" + jwa
}
