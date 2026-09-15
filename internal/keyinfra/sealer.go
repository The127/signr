package keyinfra

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// SealingKeySize is the length in bytes of the secret NewSealer takes.
const SealingKeySize = 32

// Sealer seals with AES-256-GCM and holds only the cipher's methods, so what seals stays hidden.
type Sealer struct {
	// method values instead of the AEAD, reflection stops at a func and never reaches the key
	seal func(dst, nonce, plaintext, additionalData []byte) []byte
	open func(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// NewSealer seals with the secret as an AES-256-GCM key, refusing a secret of any other length.
func NewSealer(secret []byte) (*Sealer, error) {
	if len(secret) != SealingKeySize {
		return nil, fmt.Errorf("an AES-256-GCM key is %d bytes, not %d", SealingKeySize, len(secret))
	}

	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, fmt.Errorf("creating sealing cipher: %w", err)
	}

	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("creating sealing aead: %w", err)
	}

	return &Sealer{
		seal: aead.Seal,
		open: aead.Open,
	}, nil
}

// Seal returns the plaintext sealed for Open with the same associated data.
func (sealer *Sealer) Seal(plaintext []byte, associatedData []byte) ([]byte, error) {
	return sealer.seal(nil, nil, plaintext, associatedData), nil
}

// Open returns the plaintext of a ciphertext Seal produced with the same associated data.
func (sealer *Sealer) Open(ciphertext []byte, associatedData []byte) ([]byte, error) {
	plaintext, err := sealer.open(nil, nil, ciphertext, associatedData)
	if err != nil {
		return nil, fmt.Errorf("opening sealed data: %w", err)
	}

	return plaintext, nil
}
