package backendtest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func (s *Suite) TestAnRSAKeySignsWhatTheStandardLibraryVerifies() {
	// arrange
	key := s.newKey("RS256")
	message := []byte("hello")
	digest := sha256.Sum256(message)

	// act
	signature, err := key.Sign(message)

	// assert
	s.Require().NoError(err)
	publicKey, err := key.PublicKey()
	s.Require().NoError(err)
	s.NoError(rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], signature))
}

func (s *Suite) TestAnRSAKeyVerifiesItsOwnSignature() {
	for _, algorithm := range []string{"RS256", "RS384", "RS512"} {
		s.Run(algorithm, func() {
			// arrange
			key := s.newKey(algorithm)
			message := []byte("hello")
			signature, err := key.Sign(message)
			s.Require().NoError(err)

			// act
			err = key.Verify(message, signature)

			// assert
			s.NoError(err)
		})
	}
}

func (s *Suite) TestASignerSignsADigestTheStandardLibraryVerifies() {
	// arrange
	key := s.newKey("RS256")
	digest := sha256.Sum256([]byte("hello"))
	signer, err := key.Signer()
	s.Require().NoError(err)

	// act
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)

	// assert
	s.Require().NoError(err)
	s.NoError(rsa.VerifyPKCS1v15(signer.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], signature))
}
