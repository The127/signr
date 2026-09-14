package memory

import (
	"crypto"
	"io"

	"github.com/The127/signr/internal/keyinfra"
)

type opaqueSigner struct {
	public keyinfra.KeptPublicKey
	// a method value instead of the signer, fmt and reflect cannot reach through it to the private key
	sign func(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}

// Public is a copy of the public half of the key that the caller owns.
func (s opaqueSigner) Public() crypto.PublicKey {
	return s.public.Copy()
}

// Sign signs the digest with the key, passing opts through unchanged.
func (s opaqueSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.sign(rand, digest, opts)
}
