package keyinfra_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/The127/signr/internal/keyinfra"
)

type recordingWrapper struct {
	dataKey []byte
}

func (wrapper *recordingWrapper) wrap(dataKey []byte) ([]byte, error) {
	wrapper.dataKey = bytes.Clone(dataKey)

	return []byte("wrapped"), nil
}

func (wrapper *recordingWrapper) unwrap(wrapped []byte) ([]byte, error) {
	if !bytes.Equal(wrapped, []byte("wrapped")) {
		return nil, errors.New("not the wrapped key")
	}

	return bytes.Clone(wrapper.dataKey), nil
}

func openStream(sealed []byte, associatedData []byte, unwrap func([]byte) ([]byte, error)) ([]byte, error) {
	reader, err := keyinfra.OpenStream(bytes.NewReader(sealed), associatedData, unwrap)
	if err != nil {
		return nil, err
	}

	return io.ReadAll(reader)
}

func sealStream(t *testing.T, associatedData []byte, wrap func([]byte) ([]byte, error), plaintext []byte) []byte {
	t.Helper()

	var sealed bytes.Buffer

	writer, err := keyinfra.SealStream(&sealed, associatedData, wrap)
	require.NoError(t, err)

	_, err = writer.Write(plaintext)
	require.NoError(t, err)

	err = writer.Close()
	require.NoError(t, err)

	return sealed.Bytes()
}

func TestASealedStreamIsAVersionByteTheWrappedKeyAndChunksTheStandardLibraryOpens(t *testing.T) {
	// arrange
	wrapper := &recordingWrapper{}

	// act
	sealed := sealStream(t, []byte("label"), wrapper.wrap, []byte("hello"))

	// assert
	require.Len(t, wrapper.dataKey, 32)
	require.Greater(t, len(sealed), 10)
	assert.Equal(t, byte(1), sealed[0])
	assert.Equal(t, []byte{0, 7}, sealed[1:3])
	assert.Equal(t, []byte("wrapped"), sealed[3:10])
	block, err := aes.NewCipher(wrapper.dataKey)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	lastChunkNonce := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	opened, err := gcm.Open(nil, lastChunkNonce, sealed[10:], []byte("\x01label"))
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), opened)
}

func TestOpenStreamReturnsWhatSealStreamSealed(t *testing.T) {
	// arrange
	wrapper := &recordingWrapper{}
	sealed := sealStream(t, []byte("label"), wrapper.wrap, []byte("hello"))

	// act
	opened, err := openStream(sealed, []byte("label"), wrapper.unwrap)

	// assert
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), opened)
}

const chunkSize = 64 * 1024

const sealedChunkSize = chunkSize + 16

func TestOpeningAStreamWithOtherAssociatedDataFailsClosed(t *testing.T) {
	wrapper := &recordingWrapper{}
	sealed := sealStream(t, []byte("label"), wrapper.wrap, []byte("hello"))

	for _, other := range [][]byte{nil, []byte("labex"), []byte("label\x00")} {
		t.Run(fmt.Sprintf("%q", other), func(t *testing.T) {
			// act
			_, err := openStream(sealed, other, wrapper.unwrap)

			// assert
			assert.Error(t, err)
		})
	}
}

func TestOpeningAStreamWithAFlippedBitAnywhereFailsClosed(t *testing.T) {
	wrapper := &recordingWrapper{}
	sealed := sealStream(t, []byte("label"), wrapper.wrap, []byte("hello"))

	for index := range sealed {
		t.Run(fmt.Sprintf("byte %d", index), func(t *testing.T) {
			// arrange
			tampered := bytes.Clone(sealed)
			tampered[index] ^= 0x01

			// act
			_, err := openStream(tampered, []byte("label"), wrapper.unwrap)

			// assert
			assert.Error(t, err)
		})
	}
}

func TestOpeningATruncatedStreamFailsClosedInsteadOfPanicking(t *testing.T) {
	wrapper := &recordingWrapper{}
	sealed := sealStream(t, []byte("label"), wrapper.wrap, []byte("hello"))

	for length := range sealed {
		t.Run(fmt.Sprintf("%d bytes", length), func(t *testing.T) {
			// act
			_, err := openStream(sealed[:length], []byte("label"), wrapper.unwrap)

			// assert
			assert.Error(t, err)
		})
	}
}

func TestOpeningAStreamWithAnotherDataKeyFailsClosed(t *testing.T) {
	// arrange
	wrapper := &recordingWrapper{}
	sealed := sealStream(t, nil, wrapper.wrap, []byte("hello"))
	other := &recordingWrapper{}
	sealStream(t, nil, other.wrap, []byte("hello"))

	// act
	_, err := openStream(sealed, nil, other.unwrap)

	// assert
	assert.Error(t, err)
}

func TestAnUnwrappedKeyOfAnotherSizeIsRefusedBeforeAnyChunkIsRead(t *testing.T) {
	// arrange
	wrapper := &recordingWrapper{}
	sealed := sealStream(t, nil, wrapper.wrap, []byte("hello"))
	short := func([]byte) ([]byte, error) {
		return wrapper.dataKey[:16], nil
	}

	// act
	_, err := keyinfra.OpenStream(bytes.NewReader(sealed), nil, short)

	// assert
	assert.ErrorContains(t, err, "16 bytes")
}

func TestAStreamOfAnotherVersionIsRefusedBeforeTheKeyIsUnwrapped(t *testing.T) {
	// arrange
	wrapper := &recordingWrapper{}
	sealed := sealStream(t, nil, wrapper.wrap, []byte("hello"))
	sealed[0] = 2
	unwrapped := false
	spy := func(wrapped []byte) ([]byte, error) {
		unwrapped = true

		return wrapper.unwrap(wrapped)
	}

	// act
	_, err := keyinfra.OpenStream(bytes.NewReader(sealed), nil, spy)

	// assert
	assert.ErrorContains(t, err, "version 2")
	assert.False(t, unwrapped)
}

func TestAWrappedKeyTheHeaderCannotHoldIsRefused(t *testing.T) {
	// arrange
	huge := func([]byte) ([]byte, error) {
		return make([]byte, 65536), nil
	}

	// act
	_, err := keyinfra.SealStream(&bytes.Buffer{}, nil, huge)

	// assert
	assert.ErrorContains(t, err, "65536 bytes")
}

func TestEveryFullChunkIsFollowedByAnotherAndTheLastOneMayBeEmptyOnlyForNoData(t *testing.T) {
	wrapper := &recordingWrapper{}

	for name, plaintext := range map[string][]byte{
		"nothing":             {},
		"one byte":            {1},
		"one chunk":           bytes.Repeat([]byte{1}, chunkSize),
		"one chunk and a bit": bytes.Repeat([]byte{1}, chunkSize+1),
		"three chunks":        bytes.Repeat([]byte{1}, 3*chunkSize),
	} {
		t.Run(name, func(t *testing.T) {
			// act
			sealed := sealStream(t, nil, wrapper.wrap, plaintext)

			// assert
			chunks := max(1, (len(plaintext)+chunkSize-1)/chunkSize)
			assert.Len(t, sealed, 10+len(plaintext)+16*chunks)
			opened, err := openStream(sealed, nil, wrapper.unwrap)
			require.NoError(t, err)
			assert.Equal(t, plaintext, opened)
		})
	}
}

func TestTheStreamIsTheSameShapeHoweverItWasWritten(t *testing.T) {
	// arrange
	wrapper := &recordingWrapper{}
	var sealed bytes.Buffer
	writer, err := keyinfra.SealStream(&sealed, nil, wrapper.wrap)
	require.NoError(t, err)
	plaintext := bytes.Repeat([]byte{1}, 2*chunkSize+5)

	// act
	for _, piece := range [][]byte{plaintext[:3], plaintext[3 : chunkSize+1], plaintext[chunkSize+1:]} {
		_, err = writer.Write(piece)
		require.NoError(t, err)
	}
	err = writer.Close()

	// assert
	require.NoError(t, err)
	assert.Len(t, sealed.Bytes(), 10+len(plaintext)+16*3)
	opened, err := openStream(sealed.Bytes(), nil, wrapper.unwrap)
	require.NoError(t, err)
	assert.Equal(t, plaintext, opened)
}

func TestChunksOutOfOrderDroppedDuplicatedOrFollowedByMoreFailClosed(t *testing.T) {
	wrapper := &recordingWrapper{}
	plaintext := slices.Concat(bytes.Repeat([]byte{1}, chunkSize), bytes.Repeat([]byte{2}, chunkSize), []byte("tail"))
	sealed := sealStream(t, nil, wrapper.wrap, plaintext)
	header := sealed[:10]
	first := sealed[10 : 10+sealedChunkSize]
	second := sealed[10+sealedChunkSize : 10+2*sealedChunkSize]
	last := sealed[10+2*sealedChunkSize:]

	for name, rearranged := range map[string][]byte{
		"the first two chunks swapped":       slices.Concat(header, second, first, last),
		"the first chunk dropped":            slices.Concat(header, second, last),
		"the last chunk dropped":             slices.Concat(header, first, second),
		"the first chunk twice":              slices.Concat(header, first, first, second, last),
		"the last chunk twice":               slices.Concat(header, first, second, last, last),
		"a byte after the last chunk":        slices.Concat(header, first, second, last, []byte{0}),
		"a whole chunk after the last chunk": slices.Concat(header, first, second, last, first),
		"only the last chunk":                slices.Concat(header, last),
	} {
		t.Run(name, func(t *testing.T) {
			// act
			_, err := openStream(rearranged, nil, wrapper.unwrap)

			// assert
			assert.Error(t, err)
		})
	}
}

type headerOnlyWriter struct {
	written int
}

func (writer *headerOnlyWriter) Write(data []byte) (int, error) {
	if writer.written > 0 {
		return 0, errors.New("disk full")
	}

	writer.written += len(data)

	return len(data), nil
}

func TestClosingAgainAfterTheFinalChunkFailedToWriteReportsTheFailureAgain(t *testing.T) {
	// arrange
	wrapper := &recordingWrapper{}
	writer, err := keyinfra.SealStream(&headerOnlyWriter{}, nil, wrapper.wrap)
	require.NoError(t, err)
	err = writer.Close()
	require.ErrorContains(t, err, "disk full")

	// act
	err = writer.Close()

	// assert
	assert.ErrorContains(t, err, "disk full")
}
