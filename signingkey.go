package signr

import "crypto"

// SigningKey represents an interface for cryptographic signing operations and metadata retrieval.
type SigningKey interface {
	// Sign generates a digital signature for the provided data using the private key associated with the SigningKey.
	Sign(data []byte) ([]byte, error)

	// Verify checks if the provided signature is valid for the given data using the public key.
	Verify(data, signature []byte) error

	// PublicKey returns a copy of the public key that the caller owns, for verification or distribution.
	PublicKey() (crypto.PublicKey, error)

	// Signer exposes the key as a crypto.Signer for the standard library's TLS, SSH and certificate APIs. It signs only
	// with the key's own algorithm, RSA never with PSS, and the private key stays with the backend.
	Signer() (crypto.Signer, error)

	// Algorithm returns the name of the cryptographic algorithm associated with the key, e.g., "RS256".
	Algorithm() string

	// KeyID returns a unique identifier for this signing key, used to differentiate it from other keys.
	KeyID() string
}
