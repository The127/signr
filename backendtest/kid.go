package backendtest

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
)

// RFC 7638: SHA-256 over the required public members in lexicographic order, no whitespace.
func thumbprint(json string) string {
	digest := sha256.Sum256([]byte(json))

	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (s *Suite) TestAnEdDSAKeyIDIsItsJWKThumbprint() {
	// arrange
	key := s.newKey("EdDSA")
	publicKey, err := key.PublicKey()
	s.Require().NoError(err)
	x := base64.RawURLEncoding.EncodeToString(publicKey.(ed25519.PublicKey))

	// act
	kid := key.KeyID()

	// assert
	s.Equal(thumbprint(`{"crv":"Ed25519","kty":"OKP","x":"`+x+`"}`), kid)
}

func (s *Suite) TestAnRSAKeyIDIsItsJWKThumbprint() {
	// arrange
	key := s.newKey("RS256")
	publicKey, err := key.PublicKey()
	s.Require().NoError(err)
	rsaKey := publicKey.(*rsa.PublicKey)
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes())
	n := base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes())

	// act
	kid := key.KeyID()

	// assert
	s.Equal(thumbprint(`{"e":"`+e+`","kty":"RSA","n":"`+n+`"}`), kid)
}
