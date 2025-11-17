package memory

import (
	"crypto"
	"fmt"
	"time"

	"github.com/The127/signr/utils/keyinfra"
)

type keyVersions []*signingKey

type signingKey struct {
	kid              string
	algorithm        string
	publicKey        crypto.PublicKey
	privateKey       crypto.PrivateKey
	createdTimestamp time.Time
	active           bool
}

func (s signingKey) Algorithm() string {
	return s.algorithm
}

func (s signingKey) getHashAlgorithm() crypto.Hash {
	switch s.algorithm {
	case "RS256":
		return crypto.SHA256
	case "RS384":
		return crypto.SHA384
	case "RS512":
		return crypto.SHA512
	case "EdDSA":
		return crypto.Hash(0)
	default:
		panic(fmt.Sprintf("unsupported algorithm: %s", s.algorithm))
	}
}

func (s signingKey) Sign(data []byte) ([]byte, error) {
	signed, err := keyinfra.Sign(s.privateKey, s.getHashAlgorithm(), data)
	if err != nil {
		return nil, fmt.Errorf("signing data: %w", err)
	}

	return signed, nil
}

func (s signingKey) Verify(data []byte, signature []byte) error {
	err := keyinfra.Verify(s.publicKey, s.getHashAlgorithm(), data, signature)
	if err != nil {
		return fmt.Errorf("verifying signature: %w", err)
	}

	return nil
}

func (s signingKey) PublicKey() (crypto.PublicKey, error) {
	return s.publicKey, nil
}

func (s signingKey) KeyID() string {
	return s.kid
}
