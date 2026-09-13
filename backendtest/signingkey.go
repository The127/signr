package backendtest

import (
	"crypto/ed25519"
)

func (s *Suite) TestAnUnknownAlgorithmIsRefusedInsteadOfPanicking() {
	// arrange
	manager := s.newManager()

	// act
	_, err := manager.GetGroup("signing").GetKey("ES256")

	// assert
	s.ErrorContains(err, "ES256")
}

func (s *Suite) TestAnEdDSAKeySignsWhatTheStandardLibraryVerifies() {
	// arrange
	key := s.newKey("EdDSA")
	message := []byte("hello")

	// act
	signature, err := key.Sign(message)

	// assert
	s.Require().NoError(err)
	publicKey, err := key.PublicKey()
	s.Require().NoError(err)
	s.True(ed25519.Verify(publicKey.(ed25519.PublicKey), message, signature))
}

func (s *Suite) TestAnEdDSAKeyVerifiesItsOwnSignature() {
	// arrange
	key := s.newKey("EdDSA")
	message := []byte("hello")
	signature, err := key.Sign(message)
	s.Require().NoError(err)

	// act
	err = key.Verify(message, signature)

	// assert
	s.NoError(err)
}

func (s *Suite) TestAKeyRefusesASignatureOverAnotherMessage() {
	// arrange
	key := s.newKey("EdDSA")
	signature, err := key.Sign([]byte("hello"))
	s.Require().NoError(err)

	// act
	err = key.Verify([]byte("goodbye"), signature)

	// assert
	s.Error(err)
}

func (s *Suite) TestASignerHoldsTheKeysPublicKey() {
	// arrange
	key := s.newKey("EdDSA")
	publicKey, err := key.PublicKey()
	s.Require().NoError(err)

	// act
	signer, err := key.Signer()

	// assert
	s.Require().NoError(err)
	s.Equal(publicKey, signer.Public())
}
