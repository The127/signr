package signr

import "crypto"

// SigningKey represents an interface for cryptographic signing operations and metadata retrieval.
type SigningKey interface {

	// Sign generates a digital signature for the provided data using the private key associated with the SigningKey.
	Sign(data []byte) ([]byte, error)

	// Verify checks if the provided signature is valid for the given data using the public key.
	Verify(data, signature []byte) error

	// PublicKey retrieves the public key associated with the SigningKey for verification or distribution purposes.
	PublicKey() (crypto.PublicKey, error)

	// Algorithm returns the name of the cryptographic algorithm associated with the key, e.g., "RS256".
	Algorithm() string

	// KeyID returns a unique identifier for this signing key, used to differentiate it from other keys.
	KeyID() string
}
