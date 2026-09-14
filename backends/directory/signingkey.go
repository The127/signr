package directory

import (
	"crypto"
	"errors"
)

type signingKey struct {
	kid string
}

// Algorithm is not known yet.
func (key signingKey) Algorithm() string {
	return ""
}

// Sign refuses until the key can sign.
func (key signingKey) Sign(_ []byte) ([]byte, error) {
	return nil, errors.New("directory backend cannot sign yet")
}

// Verify refuses every signature until the key can verify.
func (key signingKey) Verify(_ []byte, _ []byte) error {
	return errors.New("directory backend cannot verify yet")
}

// PublicKey is not known yet.
func (key signingKey) PublicKey() (crypto.PublicKey, error) {
	return nil, errors.New("directory backend cannot answer a public key yet")
}

// Signer refuses until the key can sign.
func (key signingKey) Signer() (crypto.Signer, error) {
	return nil, errors.New("directory backend cannot sign yet")
}

// KeyID is the RFC 7638 thumbprint of the public key.
func (key signingKey) KeyID() string {
	return key.kid
}
