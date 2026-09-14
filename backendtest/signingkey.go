package backendtest

import (
	"crypto/ed25519"
	"crypto/rsa"
	"reflect"
)

func (s *Suite) TestAnUnknownAlgorithmIsRefusedInsteadOfPanicking() {
	// arrange
	manager := s.newManager()

	// act
	_, err := manager.GetGroup("signing").GetKey("ES256")

	// assert
	s.ErrorContains(err, "ES256")
}

func (s *Suite) TestAGroupAnswersTheSameKeyTwice() {
	// arrange
	group := s.newManager().GetGroup("signing")
	first, err := group.GetKey("EdDSA")
	s.Require().NoError(err)

	// act
	second, err := group.GetKey("EdDSA")

	// assert
	s.Require().NoError(err)
	s.Equal(first.KeyID(), second.KeyID())
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

func (s *Suite) TestASignerHoldsNoPrivateKeyReflectionCanReach() {
	for _, algorithm := range []string{"EdDSA", "RS256", "RS384", "RS512"} {
		s.Run(algorithm, func() {
			// arrange
			key := s.newKey(algorithm)
			signer, err := key.Signer()
			s.Require().NoError(err)

			// act
			reaches := reachesPrivateKey(reflect.ValueOf(signer))

			// assert
			s.False(reaches)
		})
	}
}

func reachesPrivateKey(value reflect.Value) bool {
	if !value.IsValid() {
		return false
	}

	if value.Type() == reflect.TypeFor[ed25519.PrivateKey]() {
		return true
	}

	if value.Type() == reflect.TypeFor[rsa.PrivateKey]() {
		return true
	}

	switch value.Kind() {
	case reflect.Pointer, reflect.Interface:
		return reachesPrivateKey(value.Elem())

	case reflect.Struct:
		for index := range value.NumField() {
			if reachesPrivateKey(value.Field(index)) {
				return true
			}
		}

		return false

	case reflect.Slice, reflect.Array:
		for index := range value.Len() {
			if reachesPrivateKey(value.Index(index)) {
				return true
			}
		}

		return false

	case reflect.Map:
		iterator := value.MapRange()
		for iterator.Next() {
			if reachesPrivateKey(iterator.Key()) {
				return true
			}

			if reachesPrivateKey(iterator.Value()) {
				return true
			}
		}

		return false

	default:
		return false
	}
}
