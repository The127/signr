package keyinfra

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"

	// hash.New panics for a hash the binary did not link, and no consumer
	// should have to import these for RS256 to RS512 to work
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// Sign signs data with the signer, hashing it first when the algorithm has a hash. This is the one call every
// backend's key answers, an HSM's signer included, so a signature never depends on holding the private key.
func Sign(signer crypto.Signer, hash crypto.Hash, data []byte) ([]byte, error) {
	if _, ok := signer.Public().(ed25519.PublicKey); ok && hash != 0 {
		return nil, errors.New("ed25519 signs the message itself, not a hash")
	}

	digested, err := digest(hash, data)
	if err != nil {
		return nil, err
	}

	signature, err := signer.Sign(rand.Reader, digested, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return signature, nil
}

// Verify validates the signature over data with the public key, hashing data the way Sign did.
// It supports RSA and Ed25519 public key types and returns an error if verification fails or the key type is unsupported.
func Verify(publicKey crypto.PublicKey, hash crypto.Hash, data, signature []byte) error {
	switch publicKey := publicKey.(type) {
	case *rsa.PublicKey:
		digested, err := digest(hash, data)
		if err != nil {
			return err
		}

		err = rsa.VerifyPKCS1v15(publicKey, hash, digested, signature)
		if err != nil {
			return fmt.Errorf("failed to verify signature: %w", err)
		}

		return nil

	case ed25519.PublicKey:
		if hash != 0 {
			return errors.New("ed25519 signs the message itself, not a hash")
		}

		if !ed25519.Verify(publicKey, data, signature) {
			return errors.New("invalid ed25519 signature")
		}

		return nil

	default:
		return fmt.Errorf("unsupported key type: %T", publicKey)
	}
}

// A hash of zero means the algorithm signs the message itself.
func digest(hash crypto.Hash, data []byte) ([]byte, error) {
	if hash == 0 {
		return data, nil
	}

	if !hash.Available() {
		return nil, fmt.Errorf("hash %s is not available", hash)
	}

	hasher := hash.New()
	hasher.Write(data)

	return hasher.Sum(nil), nil
}
