package memory

import (
	"crypto/rand"
	"fmt"

	"github.com/The127/signr"
	"github.com/The127/signr/internal/keyinfra"
)

// GetSealingKey returns the group's key for sealing data, generating it on the first call.
func (g *keyGroup) GetSealingKey(algorithm string) (signr.SealingKey, error) {
	if algorithm != "A256GCM" {
		return nil, fmt.Errorf("unsupported algorithm %q", algorithm)
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if g.sealing != nil {
		return g.sealing, nil
	}

	secret := make([]byte, keyinfra.SealingKeySize)
	_, err := rand.Read(secret)
	if err != nil {
		return nil, fmt.Errorf("generating sealing key: %w", err)
	}

	sealer, err := keyinfra.NewSealer(secret)
	if err != nil {
		return nil, err
	}

	g.sealing = sealer

	return g.sealing, nil
}
