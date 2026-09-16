package keyinfra_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/The127/signr/internal/keyinfra"
)

func seal(t *testing.T, sealer *keyinfra.Sealer, plaintext []byte) []byte {
	t.Helper()

	var sealed bytes.Buffer

	writer, err := sealer.Seal(&sealed, []byte("label"))
	require.NoError(t, err)

	_, err = writer.Write(plaintext)
	require.NoError(t, err)

	err = writer.Close()
	require.NoError(t, err)

	return sealed.Bytes()
}

func open(sealer *keyinfra.Sealer, sealed []byte) ([]byte, error) {
	reader, err := sealer.Open(bytes.NewReader(sealed), []byte("label"))
	if err != nil {
		return nil, err
	}

	return io.ReadAll(reader)
}

// RFC 3394 section 2.2.2 unwrap, written here so the header is checked against the standard and not against the
// library that wrapped it
func unwrapRFC3394(t *testing.T, kek []byte, wrapped []byte) []byte {
	t.Helper()

	block, err := aes.NewCipher(kek)
	require.NoError(t, err)
	require.Zero(t, len(wrapped)%8)

	n := len(wrapped)/8 - 1
	a := bytes.Clone(wrapped[:8])
	r := make([][]byte, n)
	for i := range n {
		r[i] = bytes.Clone(wrapped[8*(i+1) : 8*(i+2)])
	}

	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			binary.BigEndian.PutUint64(a, binary.BigEndian.Uint64(a)^uint64(n*j+i))
			b := slices.Concat(a, r[i-1])
			block.Decrypt(b, b)
			a = b[:8]
			r[i-1] = b[8:]
		}
	}

	require.Equal(t, bytes.Repeat([]byte{0xA6}, 8), a)

	return slices.Concat(r...)
}

func TestASealedValueCarriesTheDataKeyWrappedWithA256KWUnderTheSecret(t *testing.T) {
	// arrange
	secret := bytes.Repeat([]byte{7}, keyinfra.SealingKeySize)
	sealer, err := keyinfra.NewSealer(secret)
	require.NoError(t, err)

	// act
	sealed := seal(t, sealer, []byte("hello"))

	// assert
	require.Greater(t, len(sealed), 43)
	assert.Equal(t, []byte{1, 0, 40}, sealed[:3])
	dataKey := unwrapRFC3394(t, secret, sealed[3:43])
	require.Len(t, dataKey, 32)
	block, err := aes.NewCipher(dataKey)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	lastChunkNonce := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	opened, err := gcm.Open(nil, lastChunkNonce, sealed[43:], []byte("\x01label"))
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), opened)
}

func TestASealerOpensWhatItSealed(t *testing.T) {
	// arrange
	sealer, err := keyinfra.NewSealer(bytes.Repeat([]byte{7}, keyinfra.SealingKeySize))
	require.NoError(t, err)
	sealed := seal(t, sealer, []byte("hello"))

	// act
	opened, err := open(sealer, sealed)

	// assert
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), opened)
}

func TestASealerWithAnotherSecretFailsClosed(t *testing.T) {
	// arrange
	sealer, err := keyinfra.NewSealer(bytes.Repeat([]byte{7}, keyinfra.SealingKeySize))
	require.NoError(t, err)
	other, err := keyinfra.NewSealer(bytes.Repeat([]byte{8}, keyinfra.SealingKeySize))
	require.NoError(t, err)
	sealed := seal(t, sealer, []byte("hello"))

	// act
	_, err = open(other, sealed)

	// assert
	assert.Error(t, err)
}
