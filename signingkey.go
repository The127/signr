package signr

import "crypto"

type SigningKey interface {
	Sign(data []byte) ([]byte, error)
	Verify(data, signature []byte) error

	PublicKey() (crypto.PublicKey, error)

	Algorithm() string
	KeyID() string
}
