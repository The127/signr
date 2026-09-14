package keyinfra

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// KeyID is the RFC 7638 thumbprint of a public key, or an error naming a key type it has none for.
func KeyID(publicKey crypto.PublicKey) (string, error) {
	switch publicKey := publicKey.(type) {
	case ed25519.PublicKey:
		return computeEdDSAPublicKeyKid(publicKey)

	case *rsa.PublicKey:
		return computeRSAPublicKeyKid(publicKey)

	default:
		return "", fmt.Errorf("unsupported key type %T", publicKey)
	}
}

// thumbprint is the RFC 7638 JWK thumbprint over the required public members. json.Marshal sorts map keys, which is
// the lexicographic order the RFC demands, and emits no whitespace.
func thumbprint(members map[string]string) (string, error) {
	canonical, err := json.Marshal(members)
	if err != nil {
		return "", fmt.Errorf("encoding jwk members: %w", err)
	}

	digest := sha256.Sum256(canonical)

	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}
