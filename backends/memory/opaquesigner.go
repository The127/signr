package memory

import (
	"crypto"
	"io"
)

type opaqueSigner struct {
	public crypto.PublicKey
	// a method value instead of the signer, fmt and reflect cannot reach through it to the private key
	sign func(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}

// Public is the public half of the key.
func (s opaqueSigner) Public() crypto.PublicKey {
	return s.public
}

// Sign signs the digest with the key, passing opts through unchanged.
func (s opaqueSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.sign(rand, digest, opts)
}
