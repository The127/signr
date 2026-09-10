package jwtmethod

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"

	"github.com/The127/signr"
)

// jwtSigningMethod represents a JWT signing method using a cryptographic SigningKey.
// It implements the jwt.SigningMethod interface.
type jwtSigningMethod struct {
	signingKey signr.SigningKey
}

// NewJwtSigningMethod creates a new JWT signing method using the provided signing key.
// It returns a jwt.SigningMethod implementation for signing operations.
// The result should not be registered with the jwt.RegisterSigningMethod function.
// Instead, it should be used directly when creating a new jwt.Token.
// For verifying signatures, the signing key's public key should be used instead.
func NewJwtSigningMethod(signingKey signr.SigningKey) jwt.SigningMethod {
	return &jwtSigningMethod{
		signingKey: signingKey,
	}
}

// Alg returns the name of the cryptographic algorithm associated with the signing key.
func (s *jwtSigningMethod) Alg() string { return s.signingKey.Algorithm() }

// Sign generates a digital signature for the provided signing string using the associated SigningKey.
// The passed in key is ignored. Instead, the signing key used to create the signing method is used.
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
