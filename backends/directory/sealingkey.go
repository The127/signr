package directory

import (
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/The127/signr"
	"github.com/The127/signr/internal/keyinfra"
)

const sealingAlgorithm = "AES-256-GCM"

const sealingKeyBlockType = "AES-256-GCM KEY"

// GetSealingKey returns the key the group keeps for sealing with the algorithm, generating and storing one on the
// first call.
func (group *keyGroup) GetSealingKey(algorithm string) (signr.SealingKey, error) {
	if algorithm != sealingAlgorithm {
		return nil, fmt.Errorf("unsupported algorithm %q", algorithm)
	}

	sealer, err := inGroupDirectory(group, func(keys *os.Root) (*keyinfra.Sealer, error) {
		return readOrGenerateSealer(keys, keyFile(algorithm))
	})
	if err != nil {
		return nil, err
	}

	return sealer, nil
}

func readOrGenerateSealer(keys *os.Root, file string) (*keyinfra.Sealer, error) {
	sealer, err := readSealer(keys, file)
	if errors.Is(err, fs.ErrNotExist) {
		return generateSealer(keys, file)
	}

	if err != nil {
		return nil, err
	}

	return sealer, nil
}

func generateSealer(keys *os.Root, file string) (*keyinfra.Sealer, error) {
	secret := make([]byte, keyinfra.SealingKeySize)
	_, err := rand.Read(secret)
	if err != nil {
		return nil, fmt.Errorf("generating sealing key: %w", err)
	}

	serialized := pem.EncodeToMemory(&pem.Block{
		Type:  sealingKeyBlockType,
		Bytes: secret,
	})

	err = writeOnce(keys, file, serialized)
	if errors.Is(err, errAlreadyStored) {
		return readSealer(keys, file)
	}

	if err != nil {
		return nil, fmt.Errorf("storing key: %w", err)
	}

	return keyinfra.NewSealer(secret)
}

func readSealer(keys *os.Root, file string) (*keyinfra.Sealer, error) {
	serialized, err := readPrivateFile(keys, file)
	if err != nil {
		return nil, err
	}

	block, rest := pem.Decode(serialized)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM block", file)
	}

	if block.Type != sealingKeyBlockType {
		return nil, fmt.Errorf("%s holds a %q block instead of %q", file, block.Type, sealingKeyBlockType)
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf("%s holds %d bytes after its PEM block", file, len(rest))
	}

	sealer, err := keyinfra.NewSealer(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}

	return sealer, nil
}
