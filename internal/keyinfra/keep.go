package keyinfra

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"slices"
)

// KeptPublicKey hands out copies of a public key, so no holder of a copy can rewrite the key it came from.
type KeptPublicKey struct {
	// chosen per key type in KeepPublicKey, so Copy has no unsupported type left to fail on
	copy func() crypto.PublicKey
}

// KeepPublicKey keeps a private copy of the public key, refusing a key it cannot copy.
func KeepPublicKey(publicKey crypto.PublicKey) (KeptPublicKey, error) {
	switch key := publicKey.(type) {
	case ed25519.PublicKey:
		kept := slices.Clone(key)

		return KeptPublicKey{
			copy: func() crypto.PublicKey {
				return slices.Clone(kept)
			},
		}, nil

	case *rsa.PublicKey:
		if key == nil {
			return KeptPublicKey{}, errors.New("cannot keep a nil rsa public key")
		}

		if key.N == nil {
			return KeptPublicKey{}, errors.New("cannot keep an rsa public key without a modulus")
		}

		kept := copyRSAPublicKey(key)

		return KeptPublicKey{
			copy: func() crypto.PublicKey {
				return copyRSAPublicKey(kept)
			},
		}, nil

	default:
		return KeptPublicKey{}, fmt.Errorf("cannot keep a public key of type %T", publicKey)
	}
}

// Copy is a copy of the kept public key that the caller owns.
func (key KeptPublicKey) Copy() crypto.PublicKey {
	return key.copy()
}

func copyRSAPublicKey(key *rsa.PublicKey) *rsa.PublicKey {
	return &rsa.PublicKey{
		N: new(big.Int).Set(key.N),
		E: key.E,
	}
}
