package backendtest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
)

func (s *Suite) TestAnRSAKeySignsWhatTheStandardLibraryVerifies() {
	message := []byte("hello")
	sha256Digest := sha256.Sum256(message)
	sha384Digest := sha512.Sum384(message)
	sha512Digest := sha512.Sum512(message)

	cases := []struct {
		algorithm string
		hash      crypto.Hash
		digest    []byte
	}{
		{"RS256", crypto.SHA256, sha256Digest[:]},
		{"RS384", crypto.SHA384, sha384Digest[:]},
		{"RS512", crypto.SHA512, sha512Digest[:]},
	}

	for _, signed := range cases {
		s.Run(signed.algorithm, func() {
			// arrange
			key := s.newKey(signed.algorithm)

			// act
			signature, err := key.Sign(message)

			// assert
			s.Require().NoError(err)
			publicKey, err := key.PublicKey()
			s.Require().NoError(err)
			s.NoError(rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), signed.hash, signed.digest, signature))
		})
	}
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
