package memory

import (
	"crypto"
	"fmt"
	"time"

	"github.com/The127/signr/internal/keyinfra"
)

type keyVersions []*signingKey

type signingKey struct {
	kid              string
	algorithm        string
	hash             crypto.Hash
	publicKey        crypto.PublicKey
	signer           opaqueSigner
	createdTimestamp time.Time
	active           bool
}

// Algorithm is the JWA name the key was created for.
func (s signingKey) Algorithm() string {
	return s.algorithm
}

// Sign signs data the way the algorithm prescribes.
func (s signingKey) Sign(data []byte) ([]byte, error) {
	signed, err := keyinfra.Sign(s.signer, s.hash, data)
	if err != nil {
		return nil, fmt.Errorf("signing data: %w", err)
	}

	return signed, nil
}

// Verify checks a signature Sign produced over data.
func (s signingKey) Verify(data []byte, signature []byte) error {
	err := keyinfra.Verify(s.publicKey, s.hash, data, signature)
	if err != nil {
		return fmt.Errorf("verifying signature: %w", err)
	}

	return nil
}

// PublicKey is the public half of the key.
func (s signingKey) PublicKey() (crypto.PublicKey, error) {
	return s.publicKey, nil
}

// Signer is the key as a crypto.Signer.
func (s signingKey) Signer() (crypto.Signer, error) {
	return s.signer, nil
}

// KeyID is the RFC 7638 thumbprint of the public key.
func (s signingKey) KeyID() string {
	return s.kid
}
