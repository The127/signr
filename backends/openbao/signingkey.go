package openbao

import (
	"crypto"
	"fmt"

	"github.com/The127/signr/internal/keyinfra"
)

type signingKey struct {
	kid       string
	algorithm string
	hash      crypto.Hash
	signer    transitSigner
}

// Algorithm is the JWA name the key was created for.
func (key signingKey) Algorithm() string {
	return key.algorithm
}

// Sign asks Transit to sign data the way the algorithm prescribes.
func (key signingKey) Sign(data []byte) ([]byte, error) {
	signature, err := keyinfra.Sign(key.signer, key.hash, data)
	if err != nil {
		return nil, fmt.Errorf("signing data: %w", err)
	}

	return signature, nil
}

// Verify checks a signature Sign produced over data, without asking Transit.
func (key signingKey) Verify(data []byte, signature []byte) error {
	err := keyinfra.Verify(key.signer.public, key.hash, data, signature)
	if err != nil {
		return fmt.Errorf("verifying signature: %w", err)
	}

	return nil
}

// PublicKey is the public half of the key version.
func (key signingKey) PublicKey() (crypto.PublicKey, error) {
	return key.signer.public, nil
}

// Signer is the key version as a crypto.Signer that asks Transit for every signature.
func (key signingKey) Signer() (crypto.Signer, error) {
	return key.signer, nil
}

// KeyID is the RFC 7638 thumbprint of the public key.
func (key signingKey) KeyID() string {
	return key.kid
}
