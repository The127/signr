package keyinfra

import (
	"fmt"
	"time"
)

type KeyAlgorithmStrategy interface {
	Generate(now time.Time) (*KeyPair, error)
	Import(serializedPrivateKey string) (any, any, error)
	Export(privateKey any) (string, error)
}

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
