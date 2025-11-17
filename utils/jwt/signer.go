package jwt

import (
	"encoding/base64"
	"fmt"

	"github.com/The127/signr"
)

type Signer struct {
	Key signr.SigningKey
}

func (s *Signer) Alg() string { return s.Key.Algorithm() }

func (s *Signer) Sign(signingString string, key interface{}) (string, error) {
	sig, err := s.Key.Sign([]byte(signingString))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func (s *Signer) Verify(signingString, signature string, key interface{}) error {
	isValid, err := s.Key.Verify([]byte(signingString), []byte(signature))
	if err != nil {
		return err
	}

	if !isValid {
		return fmt.Errorf("invalid signature")
	}

	return nil
}
