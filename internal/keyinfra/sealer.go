package keyinfra

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

// SealingKeySize is the length in bytes of the secret NewSealer takes.
const SealingKeySize = 32

const sealingTagSize = 16

const associatedDataHeader = jose.HeaderKey("aad")

// Sealer seals as compact JWE with dir and A256GCM and holds only functions, so what seals stays hidden.
type Sealer struct {
	// closures instead of the key, reflection stops at a func and never reaches what it captured
	seal func(plaintext []byte, options *jose.EncrypterOptions) (string, error)
	open func(sealed string) ([]byte, error)
}

type sealedHeader struct {
	AssociatedData string `json:"aad,omitempty"`
	Algorithm      string `json:"alg"`
	Encryption     string `json:"enc"`
}

// NewSealer seals with the secret as an AES-256-GCM key, refusing a secret of any other length.
func NewSealer(secret []byte) (*Sealer, error) {
	if len(secret) != SealingKeySize {
		return nil, fmt.Errorf("an AES-256-GCM key is %d bytes, not %d", SealingKeySize, len(secret))
	}

	key := bytes.Clone(secret)

	return &Sealer{
		seal: func(plaintext []byte, options *jose.EncrypterOptions) (string, error) {
			encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{
				Algorithm: jose.DIRECT,
				Key:       key,
			}, options)
			if err != nil {
				return "", err
			}

			object, err := encrypter.Encrypt(plaintext)
			if err != nil {
				return "", err
			}

			return object.CompactSerialize()
		},
		open: func(sealed string) ([]byte, error) {
			object, err := jose.ParseEncrypted(sealed, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A256GCM})
			if err != nil {
				return nil, err
			}

			return object.Decrypt(key)
		},
	}, nil
}

// Seal returns the plaintext sealed for Open with the same associated data.
func (sealer *Sealer) Seal(plaintext []byte, associatedData []byte) ([]byte, error) {
	options := &jose.EncrypterOptions{}
	if len(associatedData) > 0 {
		options = options.WithHeader(associatedDataHeader, base64.RawURLEncoding.EncodeToString(associatedData))
	}

	sealed, err := sealer.seal(plaintext, options)
	if err != nil {
		return nil, fmt.Errorf("sealing data: %w", err)
	}

	return []byte(sealed), nil
}

// Open returns the plaintext of a ciphertext Seal produced with the same associated data.
func (sealer *Sealer) Open(ciphertext []byte, associatedData []byte) ([]byte, error) {
	sealed := string(ciphertext)

	header, err := checkShape(sealed)
	if err != nil {
		return nil, fmt.Errorf("opening sealed data: %w", err)
	}

	if header.AssociatedData != base64.RawURLEncoding.EncodeToString(associatedData) {
		return nil, errors.New("opening sealed data: the associated data does not match")
	}

	plaintext, err := sealer.open(sealed)
	if err != nil {
		return nil, fmt.Errorf("opening sealed data: %w", err)
	}

	return plaintext, nil
}

// go-jose decodes leniently, ignores the parts dir does not use and works on keys in the unauthenticated header, so
// only exactly what Seal writes may reach it
func checkShape(sealed string) (sealedHeader, error) {
	parts := strings.Split(sealed, ".")
	if len(parts) != 5 {
		return sealedHeader{}, fmt.Errorf("sealed data has %d parts, a compact JWE has 5", len(parts))
	}

	decoded := make([][]byte, len(parts))
	for index, part := range parts {
		value, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return sealedHeader{}, fmt.Errorf("part %d of the sealed data is not base64url: %w", index+1, err)
		}

		if base64.RawURLEncoding.EncodeToString(value) != part {
			return sealedHeader{}, fmt.Errorf("part %d of the sealed data is not canonical base64url", index+1)
		}

		decoded[index] = value
	}

	if len(decoded[1]) != 0 {
		return sealedHeader{}, errors.New("sealed data carries an encrypted key although the key is direct")
	}

	if len(decoded[4]) != sealingTagSize {
		return sealedHeader{}, fmt.Errorf("sealed data has a %d-byte tag, not %d", len(decoded[4]), sealingTagSize)
	}

	var header sealedHeader

	err := json.Unmarshal(decoded[0], &header)
	if err != nil {
		return sealedHeader{}, fmt.Errorf("sealed data is not the header Seal writes: %w", err)
	}

	respelled, err := json.Marshal(header)
	if err != nil {
		return sealedHeader{}, fmt.Errorf("sealed data is not the header Seal writes: %w", err)
	}

	if !bytes.Equal(respelled, decoded[0]) {
		return sealedHeader{}, errors.New("sealed data is not the header Seal writes")
	}

	return header, nil
}
