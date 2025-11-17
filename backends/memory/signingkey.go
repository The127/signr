package memory

import (
	"crypto"
	"fmt"
	"time"

	"github.com/The127/signr/utils/keyinfra"
)

// keyVersions represents a list of signing keys, each associated with a key ID (KID) and cryptographic properties.
type keyVersions []*signingKey

// signingKey represents a cryptographic key pair used for signing and verifying data in a specific cryptographic algorithm.
// It includes metadata such as the key ID (kid), algorithm, creation timestamp, and an active status indicating usage.
type signingKey struct {
	kid              string
	algorithm        string
	publicKey        crypto.PublicKey
	privateKey       crypto.PrivateKey
	createdTimestamp time.Time
	active           bool
}

// Algorithm returns the name of the algorithm associated with the signing key.
func (s signingKey) Algorithm() string {
	return s.algorithm
}

// getHashAlgorithm determines and returns the appropriate hash algorithm based on the signing algorithm of the key.
func (s signingKey) getHashAlgorithm() crypto.Hash {
	switch s.algorithm {
	case "RS256":
		return crypto.SHA256
	case "RS384":
		return crypto.SHA384
	case "RS512":
		return crypto.SHA512
	case "EdDSA":
		return crypto.Hash(0)
	default:
		panic(fmt.Sprintf("unsupported algorithm: %s", s.algorithm))
	}
}

// Sign generates a digital signature of the provided data using the signingKey's private key and hashing algorithm.
func (s signingKey) Sign(data []byte) ([]byte, error) {
	signed, err := keyinfra.Sign(s.privateKey, s.getHashAlgorithm(), data)
	if err != nil {
		return nil, fmt.Errorf("signing data: %w", err)
	}

	return signed, nil
}

// Verify checks if the provided signature is valid for the given data using the signing key's public key and hash algorithm.
func (s signingKey) Verify(data []byte, signature []byte) error {
	err := keyinfra.Verify(s.publicKey, s.getHashAlgorithm(), data, signature)
	if err != nil {
		return fmt.Errorf("verifying signature: %w", err)
	}

	return nil
}

// PublicKey returns the public key associated with the signingKey and an error if retrieval fails.
func (s signingKey) PublicKey() (crypto.PublicKey, error) {
	return s.publicKey, nil
}

// KeyID returns the key identifier (kid) associated with the signing key.
func (s signingKey) KeyID() string {
	return s.kid
}
