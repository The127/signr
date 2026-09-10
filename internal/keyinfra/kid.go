package keyinfra

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

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
