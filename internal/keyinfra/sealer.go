package keyinfra

import (
	"crypto/aes"
	"fmt"
	"io"

	josecipher "github.com/go-jose/go-jose/v4/cipher"
)

// SealingKeySize is the length in bytes of the secret NewSealer takes.
const SealingKeySize = 32

// Sealer seals streams under data keys its secret wraps with A256KW, and holds only functions, so the secret stays
// hidden.
type Sealer struct {
	// closures instead of the key, reflection stops at a func and never reaches what it captured
	wrap   func(dataKey []byte) ([]byte, error)
	unwrap func(wrapped []byte) ([]byte, error)
}

// NewSealer seals with the secret as an AES-256 key wrapping key, refusing a secret of any other length.
func NewSealer(secret []byte) (*Sealer, error) {
	if len(secret) != SealingKeySize {
		return nil, fmt.Errorf("an AES-256 key is %d bytes, not %d", SealingKeySize, len(secret))
	}

	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}

	return &Sealer{
		wrap: func(dataKey []byte) ([]byte, error) {
			return josecipher.KeyWrap(block, dataKey)
		},
		unwrap: func(wrapped []byte) ([]byte, error) {
			return josecipher.KeyUnwrap(block, wrapped)
		},
	}, nil
}

// Seal returns a writer that seals what is written to it into dst for Open with the same associated data.
func (sealer *Sealer) Seal(dst io.Writer, associatedData []byte) (io.WriteCloser, error) {
	return SealStream(dst, associatedData, sealer.wrap)
}

// Open returns a reader of the plaintext of sealed data Seal produced with the same associated data.
func (sealer *Sealer) Open(src io.Reader, associatedData []byte) (io.Reader, error) {
	return OpenStream(src, associatedData, sealer.unwrap)
}
