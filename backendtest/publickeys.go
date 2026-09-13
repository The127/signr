package backendtest

import (
	"crypto"

	"github.com/The127/signr"
)

func (s *Suite) TestTheGroupListsThePublicHalfOfItsSigningKey() {
	// arrange
	group := s.newManager().GetGroup("signing")
	key, err := group.GetKey("EdDSA")
	s.Require().NoError(err)
	publicKey, err := key.PublicKey()
	s.Require().NoError(err)

	// act
	publicKeys, err := group.PublicKeys()

	// assert
	s.Require().NoError(err)
	s.Equal([]signr.PublicKey{
		{
			KeyID:     key.KeyID(),
			Algorithm: "EdDSA",
			Key:       publicKey,
		},
	}, publicKeys)
}

func (s *Suite) TestTheGroupListsTheSigningKeyOfEveryAlgorithmInAnyOrder() {
	// arrange
	group := s.newManager().GetGroup("signing")
	edKey, err := group.GetKey("EdDSA")
	s.Require().NoError(err)
	edPublicKey, err := edKey.PublicKey()
	s.Require().NoError(err)
	rsaKey, err := group.GetKey("RS256")
	s.Require().NoError(err)
	rsaPublicKey, err := rsaKey.PublicKey()
	s.Require().NoError(err)

	// act
	publicKeys, err := group.PublicKeys()

	// assert
	s.Require().NoError(err)
	s.ElementsMatch([]signr.PublicKey{
		{
			KeyID:     edKey.KeyID(),
			Algorithm: "EdDSA",
			Key:       edPublicKey,
		},
		{
			KeyID:     rsaKey.KeyID(),
			Algorithm: "RS256",
			Key:       rsaPublicKey,
		},
	}, publicKeys)
}

func (s *Suite) TestAnEmptyGroupListsNoPublicKeysInsteadOfGeneratingOne() {
	// arrange
	group := s.newManager().GetGroup("signing")

	// act
	publicKeys, err := group.PublicKeys()

	// assert
	s.Require().NoError(err)
	s.Empty(publicKeys)
}

func (s *Suite) TestAListedPublicKeyNeverCarriesPrivateMaterial() {
	for _, algorithm := range []string{"EdDSA", "RS256"} {
		s.Run(algorithm, func() {
			// arrange
			group := s.newManager().GetGroup("signing")
			_, err := group.GetKey(algorithm)
			s.Require().NoError(err)

			// act
			publicKeys, err := group.PublicKeys()

			// assert
			s.Require().NoError(err)
			s.Require().Len(publicKeys, 1)
			s.NotImplements((*crypto.Signer)(nil), publicKeys[0].Key)
		})
	}
}
