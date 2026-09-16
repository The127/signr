package backendtest

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"io"
	"reflect"

	"github.com/stretchr/testify/suite"

	"github.com/The127/signr"
)

// SealingSuite runs the sealing contract against the backend the config creates.
type SealingSuite struct {
	suite.Suite
	Backend signr.BackendConfig
}

func (s *SealingSuite) newSealingKey() signr.SealingKey {
	manager, err := signr.New(signr.Config{Backend: s.Backend})
	s.Require().NoError(err)

	key, err := manager.GetGroup("sealing").GetSealingKey("A256GCM")
	s.Require().NoError(err)

	return key
}

func (s *SealingSuite) TestOpenReturnsWhatSealSealed() {
	// arrange
	key := s.newSealingKey()
	sealed := Seal(s.T(), key, []byte("hello"), nil)

	// act
	opened, err := Open(key, sealed, nil)

	// assert
	s.Require().NoError(err)
	s.Equal([]byte("hello"), opened)
}

func (s *SealingSuite) TestOpenWithTheSameAssociatedDataReturnsWhatSealSealed() {
	// arrange
	key := s.newSealingKey()
	sealed := Seal(s.T(), key, []byte("hello"), []byte("label"))

	// act
	opened, err := Open(key, sealed, []byte("label"))

	// assert
	s.Require().NoError(err)
	s.Equal([]byte("hello"), opened)
}

func (s *SealingSuite) TestOpeningWithOtherAssociatedDataFailsClosed() {
	key := s.newSealingKey()
	sealed := Seal(s.T(), key, []byte("hello"), []byte("label"))

	for _, other := range [][]byte{nil, []byte("labex"), []byte("other label")} {
		s.Run(fmt.Sprintf("%q", other), func() {
			// act
			_, err := Open(key, sealed, other)

			// assert
			s.Error(err)
		})
	}
}

func (s *SealingSuite) TestTheCiphertextDoesNotContainThePlaintext() {
	// arrange
	key := s.newSealingKey()
	plaintext := []byte("a message that must not be readable")

	// act
	sealed := Seal(s.T(), key, plaintext, nil)

	// assert
	s.False(bytes.Contains(sealed, plaintext))
}

func (s *SealingSuite) TestSealingTwiceYieldsDifferentCiphertexts() {
	// arrange
	key := s.newSealingKey()
	first := Seal(s.T(), key, []byte("hello"), nil)

	// act
	second := Seal(s.T(), key, []byte("hello"), nil)

	// assert
	s.NotEqual(first, second)
}

func (s *SealingSuite) TestOpeningAFlippedBitAnywhereFailsClosed() {
	key := s.newSealingKey()
	sealed := Seal(s.T(), key, []byte("hello"), nil)

	for index := range sealed {
		s.Run(fmt.Sprintf("byte %d", index), func() {
			// arrange
			tampered := bytes.Clone(sealed)
			tampered[index] ^= 0x01

			// act
			_, err := Open(key, tampered, nil)

			// assert
			s.Error(err)
		})
	}
}

func (s *SealingSuite) TestOpeningATruncatedCiphertextFailsClosedInsteadOfPanicking() {
	key := s.newSealingKey()
	sealed := Seal(s.T(), key, []byte("hello"), nil)

	for length := range sealed {
		s.Run(fmt.Sprintf("%d bytes", length), func() {
			// act
			_, err := Open(key, sealed[:length], nil)

			// assert
			s.Error(err)
		})
	}
}

func (s *SealingSuite) TestAValueLargerThanOneChunkRoundTripsWrittenAndReadInPieces() {
	// arrange
	key := s.newSealingKey()
	plaintext := make([]byte, 2*64*1024+5)
	for index := range plaintext {
		plaintext[index] = byte(index)
	}
	var sealed bytes.Buffer
	writer, err := key.Seal(&sealed, []byte("label"))
	s.Require().NoError(err)
	for _, piece := range [][]byte{plaintext[:3], plaintext[3:70000], plaintext[70000:]} {
		_, err = writer.Write(piece)
		s.Require().NoError(err)
	}
	err = writer.Close()
	s.Require().NoError(err)
	s.Require().Less(sealed.Len(), len(plaintext)+200)

	// act
	reader, err := key.Open(&sealed, []byte("label"))

	// assert
	s.Require().NoError(err)
	var opened bytes.Buffer
	_, err = io.CopyBuffer(&opened, reader, make([]byte, 1000))
	s.Require().NoError(err)
	s.Equal(plaintext, opened.Bytes())
}

func (s *SealingSuite) TestClosingTheWriterAgainWritesNothingMore() {
	// arrange
	key := s.newSealingKey()
	var sealed bytes.Buffer
	writer, err := key.Seal(&sealed, nil)
	s.Require().NoError(err)
	_, err = writer.Write([]byte("hello"))
	s.Require().NoError(err)
	err = writer.Close()
	s.Require().NoError(err)
	once := bytes.Clone(sealed.Bytes())

	// act
	err = writer.Close()

	// assert
	s.Require().NoError(err)
	s.Equal(once, sealed.Bytes())
}

func (s *SealingSuite) TestWritingAfterCloseFailsClosed() {
	// arrange
	key := s.newSealingKey()
	var sealed bytes.Buffer
	writer, err := key.Seal(&sealed, nil)
	s.Require().NoError(err)
	err = writer.Close()
	s.Require().NoError(err)

	// act
	_, err = writer.Write([]byte("late"))

	// assert
	s.Error(err)
}

func (s *SealingSuite) TestAKeyFetchedAgainOpensWhatTheFirstSealed() {
	// arrange
	manager, err := signr.New(signr.Config{Backend: s.Backend})
	s.Require().NoError(err)
	group := manager.GetGroup("sealing")
	first, err := group.GetSealingKey("A256GCM")
	s.Require().NoError(err)
	sealed := Seal(s.T(), first, []byte("hello"), nil)
	again, err := group.GetSealingKey("A256GCM")
	s.Require().NoError(err)

	// act
	opened, err := Open(again, sealed, nil)

	// assert
	s.Require().NoError(err)
	s.Equal([]byte("hello"), opened)
}

func (s *SealingSuite) TestOpeningAnotherGroupsCiphertextFailsClosed() {
	// arrange
	manager, err := signr.New(signr.Config{Backend: s.Backend})
	s.Require().NoError(err)
	sealer, err := manager.GetGroup("a").GetSealingKey("A256GCM")
	s.Require().NoError(err)
	opener, err := manager.GetGroup("b").GetSealingKey("A256GCM")
	s.Require().NoError(err)
	sealed := Seal(s.T(), sealer, []byte("hello"), nil)

	// act
	_, err = Open(opener, sealed, nil)

	// assert
	s.Error(err)
}

func (s *SealingSuite) TestSealingLeavesTheGroupsPublicKeysAlone() {
	// arrange
	manager, err := signr.New(signr.Config{Backend: s.Backend})
	s.Require().NoError(err)
	group := manager.GetGroup("sealing")
	key, err := group.GetKey("EdDSA")
	s.Require().NoError(err)
	_, err = group.GetSealingKey("A256GCM")
	s.Require().NoError(err)

	// act
	publicKeys, err := group.PublicKeys()

	// assert
	s.Require().NoError(err)
	s.Require().Len(publicKeys, 1)
	s.Equal(key.KeyID(), publicKeys[0].KeyID)
}

func (s *SealingSuite) TestAnUnknownAlgorithmIsRefusedInsteadOfPanicking() {
	// arrange
	manager, err := signr.New(signr.Config{Backend: s.Backend})
	s.Require().NoError(err)

	// act
	_, err = manager.GetGroup("sealing").GetSealingKey("ChaCha20-Poly1305")

	// assert
	s.ErrorContains(err, "ChaCha20-Poly1305")
}

func (s *SealingSuite) TestASealingKeyCanBeAMapKeyInsteadOfPanicking() {
	// arrange
	key := s.newSealingKey()

	// act
	keys := map[signr.SealingKey]bool{key: true}

	// assert
	s.True(keys[key])
}

func (s *SealingSuite) TestNoCipherIsReachableByReflectionFromTheManagerTheGroupOrTheKey() {
	// arrange
	manager, err := signr.New(signr.Config{Backend: s.Backend})
	s.Require().NoError(err)
	group := manager.GetGroup("sealing")
	key, err := group.GetSealingKey("A256GCM")
	s.Require().NoError(err)
	Seal(s.T(), key, []byte("hello"), nil)

	// act
	reaches := reachesCipher(reflect.ValueOf([]any{manager, group, key}))

	// assert
	s.False(reaches)
}

type visit struct {
	address   uintptr
	valueType reflect.Type
	length    int
}

func reachesCipher(value reflect.Value) bool {
	return reachesCipherFrom(value, map[visit]bool{})
}

func reachesCipherFrom(value reflect.Value, seen map[visit]bool) bool {
	if !value.IsValid() {
		return false
	}

	// an interface field is judged by what it holds, not by the interface it is declared as
	if value.Kind() == reflect.Interface {
		return reachesCipherFrom(value.Elem(), seen)
	}

	if holdsCipher(value.Type()) {
		return true
	}

	switch value.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Map:
		if value.IsNil() {
			return false
		}

		if !firstVisit(value, seen) {
			return false
		}

		return reachesCipherInside(value, seen)

	case reflect.Struct, reflect.Array:
		return reachesCipherInside(value, seen)

	default:
		return false
	}
}

func reachesCipherInside(value reflect.Value, seen map[visit]bool) bool {
	switch value.Kind() {
	case reflect.Pointer:
		return reachesCipherFrom(value.Elem(), seen)

	case reflect.Struct:
		for index := range value.NumField() {
			if reachesCipherFrom(value.Field(index), seen) {
				return true
			}
		}

		return false

	case reflect.Slice, reflect.Array:
		for index := range value.Len() {
			if reachesCipherFrom(value.Index(index), seen) {
				return true
			}
		}

		return false

	case reflect.Map:
		iterator := value.MapRange()
		for iterator.Next() {
			if reachesCipherFrom(iterator.Key(), seen) {
				return true
			}

			if reachesCipherFrom(iterator.Value(), seen) {
				return true
			}
		}

		return false

	default:
		return false
	}
}

func holdsCipher(valueType reflect.Type) bool {
	for _, cipherType := range []reflect.Type{reflect.TypeFor[cipher.Block](), reflect.TypeFor[cipher.AEAD]()} {
		if valueType.Implements(cipherType) {
			return true
		}

		// a value whose cipher methods have pointer receivers is one address away from them
		if reflect.PointerTo(valueType).Implements(cipherType) {
			return true
		}
	}

	return false
}

// a value reached twice, or through itself, is walked once, and a shared address alone must not hide another type
func firstVisit(value reflect.Value, seen map[visit]bool) bool {
	length := 0
	if value.Kind() == reflect.Slice {
		length = value.Len()
	}

	key := visit{
		address:   value.Pointer(),
		valueType: value.Type(),
		length:    length,
	}

	if seen[key] {
		return false
	}

	seen[key] = true

	return true
}
