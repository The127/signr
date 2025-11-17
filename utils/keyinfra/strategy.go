package keyinfra

import (
	"fmt"
	"time"
)

// KeyAlgorithmStrategy defines the behavior for generating, importing, and exporting cryptographic key pairs.
type KeyAlgorithmStrategy interface {
	Generate(now time.Time) (*KeyPair, error)
	Import(serializedPrivateKey string) (any, any, error)
	Export(privateKey any) (string, error)
}

// GetKeyStrategy returns the appropriate KeyAlgorithmStrategy for the given JWA algorithm or panics if unsupported.
func GetKeyStrategy(jwa string) KeyAlgorithmStrategy {
	switch jwa {
	case "RS256", "RS384", "RS512":
		return &RSAKeyStrategy{}

	case "EdDSA":
		return &EdDSAKeyStrategy{}

	default:
		panic(fmt.Sprintf("unsupported algorithm: %s", jwa))
	}
}
