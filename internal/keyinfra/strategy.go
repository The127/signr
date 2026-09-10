package keyinfra

import (
	"crypto"
	"fmt"
	"time"
)

// KeyAlgorithmStrategy generates, imports and exports key pairs for one algorithm and says which hash its
// signatures are over, zero when the algorithm signs the message itself.
type KeyAlgorithmStrategy interface {
	Generate(now time.Time) (*KeyPair, error)
	Import(serializedPrivateKey string) (any, any, error)
	Export(privateKey any) (string, error)
	Hash() crypto.Hash
}

// GetKeyStrategy returns the strategy for a JWA algorithm name, or an error naming an unsupported one.
func GetKeyStrategy(jwa string) (KeyAlgorithmStrategy, error) {
	switch jwa {
	case "RS256":
		return &RSAKeyStrategy{hash: crypto.SHA256}, nil

	case "RS384":
		return &RSAKeyStrategy{hash: crypto.SHA384}, nil

	case "RS512":
		return &RSAKeyStrategy{hash: crypto.SHA512}, nil

	case "EdDSA":
		return &EdDSAKeyStrategy{}, nil

	default:
		return nil, fmt.Errorf("unsupported algorithm %q", jwa)
	}
}
