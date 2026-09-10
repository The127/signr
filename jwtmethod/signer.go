package jwtmethod

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"

	"github.com/The127/signr"
)

type jwtSigningMethod struct {
	signingKey signr.SigningKey
}

// NewJwtSigningMethod signs tokens with the key. It is for jwt.NewWithClaims, never for
// jwt.RegisterSigningMethod, and it does not verify.
func NewJwtSigningMethod(signingKey signr.SigningKey) jwt.SigningMethod {
	return &jwtSigningMethod{
		signingKey: signingKey,
	}
}

// Alg is the key's JWA algorithm name.
func (s *jwtSigningMethod) Alg() string { return s.signingKey.Algorithm() }

// Sign signs the signing string with the key, the key argument is ignored.
func (s *jwtSigningMethod) Sign(signingString string, _ any) ([]byte, error) {
	sig, err := s.signingKey.Sign([]byte(signingString))
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// Verify refuses, a token is verified with the key's public key and the standard jwt method for its algorithm.
func (s *jwtSigningMethod) Verify(_ string, _ []byte, _ any) error {
	return errors.New("this method only signs, verify with the signing key's public key")
}
