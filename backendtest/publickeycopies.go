package backendtest

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	"github.com/The127/signr"
)

func (s *Suite) TestRewritingAHandedOutPublicKeyCannotMakeTheKeyVerifyAnotherKey() {
	for _, algorithm := range []string{"EdDSA", "RS256"} {
		for _, route := range []string{"PublicKey", "Signer", "PublicKeys"} {
			s.Run(algorithm+"/"+route, func() {
				// arrange
				group := s.newManager().GetGroup("signing")
				key, err := group.GetKey(algorithm)
				s.Require().NoError(err)
				message := []byte("hello")
				forged := s.rewriteToAnotherKey(s.handedOutPublicKey(group, key, route), message)

				// act
				err = key.Verify(message, forged)

				// assert
				s.Error(err)
			})
		}
	}
}

func (s *Suite) handedOutPublicKey(group signr.KeyGroup, key signr.SigningKey, route string) crypto.PublicKey {
	switch route {
	case "PublicKey":
		publicKey, err := key.PublicKey()
		s.Require().NoError(err)

		return publicKey

	case "Signer":
		signer, err := key.Signer()
		s.Require().NoError(err)

		return signer.Public()

	default:
		publicKeys, err := group.PublicKeys()
		s.Require().NoError(err)
		s.Require().Len(publicKeys, 1)

		return publicKeys[0].Key
	}
}

func (s *Suite) rewriteToAnotherKey(publicKey crypto.PublicKey, message []byte) []byte {
	switch handedOut := publicKey.(type) {
	case ed25519.PublicKey:
		attackerPublic, attackerPrivate, err := ed25519.GenerateKey(rand.Reader)
		s.Require().NoError(err)
		copy(handedOut, attackerPublic)

		return ed25519.Sign(attackerPrivate, message)

	case *rsa.PublicKey:
		attacker, err := rsa.GenerateKey(rand.Reader, 2048)
		s.Require().NoError(err)
		handedOut.N.Set(attacker.N)
		handedOut.E = attacker.E
		digest := sha256.Sum256(message)
		signature, err := rsa.SignPKCS1v15(rand.Reader, attacker, crypto.SHA256, digest[:])
		s.Require().NoError(err)

		return signature

	default:
		s.FailNowf("unexpected public key type", "%T", publicKey)

		return nil
	}
}
