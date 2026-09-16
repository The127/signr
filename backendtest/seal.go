package backendtest

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/The127/signr"
)

// Seal returns the plaintext sealed by the key as one written and closed stream.
func Seal(t testing.TB, key signr.SealingKey, plaintext []byte, associatedData []byte) []byte {
	t.Helper()

	var sealed bytes.Buffer

	writer, err := key.Seal(&sealed, associatedData)
	require.NoError(t, err)

	_, err = writer.Write(plaintext)
	require.NoError(t, err)

	err = writer.Close()
	require.NoError(t, err)

	return sealed.Bytes()
}

// Open returns the plaintext the key recovers from the sealed bytes, or the first error opening or reading gives.
func Open(key signr.SealingKey, sealed []byte, associatedData []byte) ([]byte, error) {
	reader, err := key.Open(bytes.NewReader(sealed), associatedData)
	if err != nil {
		return nil, err
	}

	return io.ReadAll(reader)
}
