package memory

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/The127/signr"
)

// GetSealingKey returns the group's key for sealing data, generating it on the first call.
func (g *keyGroup) GetSealingKey(algorithm string) (signr.SealingKey, error) {
	if algorithm != "AES-256-GCM" {
		return nil, fmt.Errorf("unsupported algorithm %q", algorithm)
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	// the pointer, the funcs inside make the value itself neither comparable nor usable as a map key
	if g.sealing != nil {
		return g.sealing, nil
	}

	key, err := newSealingKey()
	if err != nil {
		return nil, err
	}

	g.sealing = &key

	return g.sealing, nil
}

func newSealingKey() (sealingKey, error) {
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	if err != nil {
		return sealingKey{}, fmt.Errorf("generating sealing key: %w", err)
	}

	block, err := aes.NewCipher(secret)
	if err != nil {
		return sealingKey{}, fmt.Errorf("creating sealing cipher: %w", err)
	}

	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return sealingKey{}, fmt.Errorf("creating sealing aead: %w", err)
	}

	return sealingKey{
		seal: aead.Seal,
		open: aead.Open,
	}, nil
}

type sealingKey struct {
	// method values instead of the AEAD, reflection stops at a func and never reaches the key
	seal func(dst, nonce, plaintext, additionalData []byte) []byte
	open func(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// Seal returns the plaintext sealed for Open with the same associated data.
func (key sealingKey) Seal(plaintext []byte, associatedData []byte) ([]byte, error) {
	return key.seal(nil, nil, plaintext, associatedData), nil
}

// Open returns the plaintext of a ciphertext Seal produced with the same associated data.
func (key sealingKey) Open(ciphertext []byte, associatedData []byte) ([]byte, error) {
	plaintext, err := key.open(nil, nil, ciphertext, associatedData)
	if err != nil {
		return nil, fmt.Errorf("opening sealed data: %w", err)
	}

	return plaintext, nil
}
