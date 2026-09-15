package directory

import (
	"crypto"
	"fmt"

	"github.com/The127/signr"
	"github.com/The127/signr/internal/keyinfra"
)

type signingKey struct {
	kid       string
	algorithm string
	hash      crypto.Hash
	publicKey keyinfra.KeptPublicKey
	signer    keyinfra.OpaqueSigner
}

func newSigningKey(privateKey any, kid string, jwa string, hash crypto.Hash) (signr.SigningKey, error) {
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("a key of type %T cannot sign", privateKey)
	}

	publicKey, err := keyinfra.KeepPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}

	return signingKey{
		kid:       kid,
		algorithm: jwa,
		hash:      hash,
		publicKey: publicKey,
		signer:    keyinfra.NewOpaqueSigner(publicKey, signer.Sign),
	}, nil
}

// Algorithm is the JWA name the key was created for.
func (key signingKey) Algorithm() string {
	return key.algorithm
}

// Sign signs data the way the algorithm prescribes.
func (key signingKey) Sign(data []byte) ([]byte, error) {
	signed, err := keyinfra.Sign(key.signer, key.hash, data)
	if err != nil {
		return nil, fmt.Errorf("signing data: %w", err)
	}

	return signed, nil
}

// Verify checks a signature Sign produced over data.
func (key signingKey) Verify(data []byte, signature []byte) error {
	err := keyinfra.Verify(key.publicKey.Copy(), key.hash, data, signature)
	if err != nil {
		return fmt.Errorf("verifying signature: %w", err)
	}

	return nil
}

// PublicKey is a copy of the public half of the key that the caller owns.
func (key signingKey) PublicKey() (crypto.PublicKey, error) {
	return key.publicKey.Copy(), nil
}

// Signer is the key as a crypto.Signer whose holder cannot reach the private key.
func (key signingKey) Signer() (crypto.Signer, error) {
	return key.signer, nil
}

// KeyID is the RFC 7638 thumbprint of the public key.
func (key signingKey) KeyID() string {
	return key.kid
}
