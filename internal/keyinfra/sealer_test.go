package keyinfra_test

import (
	"bytes"
	"encoding/base64"
	"io"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/The127/signr/internal/keyinfra"
)

func seal(t *testing.T, sealer *keyinfra.Sealer, plaintext []byte) string {
	t.Helper()

	var sealed bytes.Buffer

	writer, err := sealer.Seal(&sealed, nil)
	require.NoError(t, err)

	_, err = writer.Write(plaintext)
	require.NoError(t, err)

	err = writer.Close()
	require.NoError(t, err)

	return sealed.String()
}

func open(sealer *keyinfra.Sealer, sealed string) ([]byte, error) {
	reader, err := sealer.Open(strings.NewReader(sealed), nil)
	if err != nil {
		return nil, err
	}

	return io.ReadAll(reader)
}

func TestASealedValueIsACompactJWEThatAJOSELibraryOpensWithTheKey(t *testing.T) {
	// arrange
	secret := bytes.Repeat([]byte{7}, keyinfra.SealingKeySize)
	sealer, err := keyinfra.NewSealer(secret)
	require.NoError(t, err)

	// act
	sealed := seal(t, sealer, []byte("hello"))

	// assert
	object, err := jose.ParseEncrypted(sealed, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A256GCM})
	require.NoError(t, err)
	opened, err := object.Decrypt(secret)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), opened)
}

func TestASealedValueAlteredWithoutTheKeyFailsClosedInsteadOfOpening(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, keyinfra.SealingKeySize)
	sealer, err := keyinfra.NewSealer(secret)
	require.NoError(t, err)
	canonical := seal(t, sealer, []byte("hello"))
	parts := strings.Split(canonical, ".")
	require.Len(t, parts, 5)
	nonce, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	require.NoError(t, err)
	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	require.NoError(t, err)
	lastCiphertextByte := ciphertext[len(ciphertext)-1]

	alterations := map[string]string{
		"a trailing newline":                    canonical + "\n",
		"a newline inside the header":           canonical[:4] + "\n" + canonical[4:],
		"a leading carriage return and newline": "\r\n" + canonical,
		"an encrypted key although the key is direct": strings.Join([]string{
			parts[0], "AAAA", parts[2], parts[3], parts[4],
		}, "."),
		"a ciphertext byte moved into the tag": strings.Join([]string{
			parts[0],
			parts[1],
			parts[2],
			base64.RawURLEncoding.EncodeToString(ciphertext[:len(ciphertext)-1]),
			base64.RawURLEncoding.EncodeToString(append([]byte{lastCiphertextByte}, tag...)),
		}, "."),
		"the whole ciphertext moved into the tag": strings.Join([]string{
			parts[0],
			parts[1],
			parts[2],
			"",
			base64.RawURLEncoding.EncodeToString(append(bytes.Clone(ciphertext), tag...)),
		}, "."),
		"a shorter nonce": strings.Join([]string{
			parts[0], parts[1], base64.RawURLEncoding.EncodeToString(nonce[:8]), parts[3], parts[4],
		}, "."),
	}

	for name, altered := range alterations {
		t.Run(name, func(t *testing.T) {
			// act
			_, err := open(sealer, altered)

			// assert
			assert.Error(t, err)
		})
	}
}

func TestAHeaderSealNeverWritesIsRefusedBeforeTheKeyIsUsed(t *testing.T) {
	// arrange
	secret := bytes.Repeat([]byte{7}, keyinfra.SealingKeySize)
	sealer, err := keyinfra.NewSealer(secret)
	require.NoError(t, err)
	parts := strings.Split(seal(t, sealer, []byte("hello")), ".")
	require.Len(t, parts, 5)
	headerWithAKey := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"dir","enc":"A256GCM","jwk":{"kty":"oct","k":"AA"}}`))
	altered := strings.Join([]string{headerWithAKey, parts[1], parts[2], parts[3], parts[4]}, ".")

	// act
	_, err = open(sealer, altered)

	// assert
	assert.ErrorContains(t, err, "not the header Seal writes")
}

func TestAJWEAJOSELibrarySealedWithTheKeyOpens(t *testing.T) {
	// arrange
	secret := bytes.Repeat([]byte{7}, keyinfra.SealingKeySize)
	sealer, err := keyinfra.NewSealer(secret)
	require.NoError(t, err)
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{
		Algorithm: jose.DIRECT,
		Key:       secret,
	}, nil)
	require.NoError(t, err)
	object, err := encrypter.Encrypt([]byte("hello"))
	require.NoError(t, err)
	sealed, err := object.CompactSerialize()
	require.NoError(t, err)

	// act
	opened, err := open(sealer, sealed)

	// assert
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), opened)
}
