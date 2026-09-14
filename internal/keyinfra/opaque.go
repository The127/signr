package keyinfra

import (
	"crypto"
	"io"
)

// OpaqueSigner is a crypto.Signer that holds only a public key and a signing function, so what signs stays hidden.
type OpaqueSigner struct {
	public KeptPublicKey
	// a method value instead of the signer, fmt and reflection stop at a func and never reach what signs
	sign func(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}

// NewOpaqueSigner hides a signer behind its public key and its Sign method.
func NewOpaqueSigner(public KeptPublicKey, sign func(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)) OpaqueSigner {
	return OpaqueSigner{
		public: public,
		sign:   sign,
	}
}

// Public is a copy of the public half of the key that the caller owns.
func (signer OpaqueSigner) Public() crypto.PublicKey {
	return signer.public.Copy()
}

// Sign signs the digest with the key, passing opts through unchanged.
func (signer OpaqueSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return signer.sign(rand, digest, opts)
}
