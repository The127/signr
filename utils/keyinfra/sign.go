package keyinfra

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func Sign(privateKey crypto.PrivateKey, hash crypto.Hash, data []byte) ([]byte, error) {
	switch privateKey := privateKey.(type) {
	case *rsa.PrivateKey:
		result, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hash, data)
		if err != nil {
			return nil, fmt.Errorf("failed to sign data: %w", err)
		}

		return result, nil

	case ed25519.PrivateKey:
		return ed25519.Sign(privateKey, data), nil

	default:
		panic(fmt.Sprintf("unsupported key type: %T", privateKey))
	}
}

func Verify(publicKey crypto.PublicKey, hash crypto.Hash, data, signature []byte) error {
	switch publicKey := publicKey.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(publicKey, hash, data, signature)
		if err != nil {
			return fmt.Errorf("failed to verify signature: %w", err)
		}

		return nil

	case ed25519.PublicKey:
		verify := ed25519.Verify(publicKey, data, signature)
		if !verify {
			return fmt.Errorf("invalid ed25519 signature")
		}

		return nil

	default:
		panic(fmt.Sprintf("unsupported key type: %T", publicKey))
	}
}
