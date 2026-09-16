package keyinfra

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

const streamVersion byte = 1

const chunkSize = 64 * 1024

const chunkLimit = 1 << 32

const streamNonceSize = 12

// SealStream returns a writer that seals what is written to it into dst under a fresh data key, which wrap seals for
// the header, and Close writes the final chunk.
func SealStream(dst io.Writer, associatedData []byte, wrap func(dataKey []byte) ([]byte, error)) (io.WriteCloser, error) {
	dataKey := make([]byte, SealingKeySize)

	_, err := rand.Read(dataKey)
	if err != nil {
		return nil, fmt.Errorf("sealing data: generating the data key: %w", err)
	}

	wrapped, err := wrap(dataKey)
	if err != nil {
		return nil, fmt.Errorf("sealing data: wrapping the data key: %w", err)
	}

	if len(wrapped) > math.MaxUint16 {
		return nil, fmt.Errorf("sealing data: the wrapped data key is %d bytes, the header holds at most %d", len(wrapped), math.MaxUint16)
	}

	sealer, err := newChunkSealer(dataKey)
	if err != nil {
		return nil, fmt.Errorf("sealing data: %w", err)
	}

	header := make([]byte, 0, 3+len(wrapped))
	header = append(header, streamVersion)
	header = binary.BigEndian.AppendUint16(header, uint16(len(wrapped))) //nolint:gosec // bounded by the check above
	header = append(header, wrapped...)

	_, err = dst.Write(header)
	if err != nil {
		return nil, fmt.Errorf("sealing data: writing the header: %w", err)
	}

	return &streamWriter{
		dst:            dst,
		sealer:         sealer,
		associatedData: append([]byte{streamVersion}, associatedData...),
		chunk:          make([]byte, 0, chunkSize),
	}, nil
}

// OpenStream returns a reader of the plaintext of a stream SealStream sealed with the same associated data, with the
// data key unwrap recovers from the header, and a read error means nothing read so far can be trusted.
func OpenStream(src io.Reader, associatedData []byte, unwrap func(wrapped []byte) ([]byte, error)) (io.Reader, error) {
	header := make([]byte, 3)

	_, err := io.ReadFull(src, header)
	if err != nil {
		return nil, fmt.Errorf("opening sealed data: reading the header: %w", err)
	}

	if header[0] != streamVersion {
		return nil, fmt.Errorf("opening sealed data: version %d, this is version %d", header[0], streamVersion)
	}

	wrapped := make([]byte, binary.BigEndian.Uint16(header[1:3]))

	_, err = io.ReadFull(src, wrapped)
	if err != nil {
		return nil, fmt.Errorf("opening sealed data: reading the wrapped data key: %w", err)
	}

	dataKey, err := unwrap(wrapped)
	if err != nil {
		return nil, fmt.Errorf("opening sealed data: unwrapping the data key: %w", err)
	}

	if len(dataKey) != SealingKeySize {
		return nil, fmt.Errorf("opening sealed data: the unwrapped data key is %d bytes, not %d", len(dataKey), SealingKeySize)
	}

	opener, err := newChunkSealer(dataKey)
	if err != nil {
		return nil, fmt.Errorf("opening sealed data: %w", err)
	}

	sealedChunkSize := chunkSize + opener.Overhead()

	return &streamReader{
		src:            src,
		opener:         opener,
		associatedData: append([]byte{streamVersion}, associatedData...),
		buffers: [2][]byte{
			make([]byte, sealedChunkSize),
			make([]byte, sealedChunkSize),
		},
	}, nil
}

func newChunkSealer(dataKey []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

func chunkNonce(counter uint64, last bool) []byte {
	nonce := make([]byte, streamNonceSize)
	binary.BigEndian.PutUint64(nonce[3:11], counter)

	if last {
		nonce[11] = 1
	}

	return nonce
}

type streamWriter struct {
	dst            io.Writer
	sealer         cipher.AEAD
	associatedData []byte
	chunk          []byte
	counter        uint64
	closed         bool
	failed         error
}

func (writer *streamWriter) Write(data []byte) (int, error) {
	if writer.closed {
		return 0, errors.New("sealing data: write after close")
	}

	if writer.failed != nil {
		return 0, writer.failed
	}

	written := 0

	for len(data) > 0 {
		if len(writer.chunk) == chunkSize {
			err := writer.flush(false)
			if err != nil {
				return written, err
			}
		}

		room := chunkSize - len(writer.chunk)
		if room > len(data) {
			room = len(data)
		}

		writer.chunk = append(writer.chunk, data[:room]...)
		data = data[room:]
		written += room
	}

	return written, nil
}

func (writer *streamWriter) Close() error {
	if writer.failed != nil {
		return writer.failed
	}

	if writer.closed {
		return nil
	}

	writer.closed = true

	return writer.flush(true)
}

func (writer *streamWriter) flush(last bool) error {
	if writer.counter == chunkLimit {
		writer.failed = fmt.Errorf("sealing data: a stream holds at most %d chunks", chunkLimit)

		return writer.failed
	}

	sealed := writer.sealer.Seal(nil, chunkNonce(writer.counter, last), writer.chunk, writer.associatedData)

	_, err := writer.dst.Write(sealed)
	if err != nil {
		writer.failed = fmt.Errorf("sealing data: writing chunk %d: %w", writer.counter, err)

		return writer.failed
	}

	writer.counter++
	writer.chunk = writer.chunk[:0]

	return nil
}

type streamReader struct {
	src            io.Reader
	opener         cipher.AEAD
	associatedData []byte
	buffers        [2][]byte
	ahead          []byte
	exhausted      bool
	primed         bool
	plaintext      []byte
	counter        uint64
	done           bool
	failed         error
}

func (reader *streamReader) Read(buffer []byte) (int, error) {
	if reader.failed != nil {
		return 0, reader.failed
	}

	for len(reader.plaintext) == 0 {
		if reader.done {
			return 0, io.EOF
		}

		err := reader.openNextChunk()
		if err != nil {
			reader.failed = err

			return 0, err
		}
	}

	read := copy(buffer, reader.plaintext)
	reader.plaintext = reader.plaintext[read:]

	return read, nil
}

func (reader *streamReader) openNextChunk() error {
	sealed, last, err := reader.nextSealedChunk()
	if err != nil {
		return err
	}

	if reader.counter == chunkLimit {
		return fmt.Errorf("opening sealed data: a stream holds at most %d chunks", chunkLimit)
	}

	plaintext, err := reader.opener.Open(nil, chunkNonce(reader.counter, last), sealed, reader.associatedData)
	if err != nil {
		return fmt.Errorf("opening sealed data: chunk %d: %w", reader.counter, err)
	}

	reader.plaintext = plaintext
	reader.counter++
	reader.done = last

	return nil
}

// whether a chunk is the last one is decided by what follows it, never by the chunk itself
func (reader *streamReader) nextSealedChunk() ([]byte, bool, error) {
	if !reader.primed {
		err := reader.readAhead(reader.buffers[0])
		if err != nil {
			return nil, false, err
		}

		reader.primed = true
	}

	chunk := reader.ahead

	if reader.exhausted {
		if len(chunk) < reader.opener.Overhead() {
			return nil, false, errors.New("opening sealed data: the stream ends without a final chunk")
		}

		return chunk, true, nil
	}

	err := reader.readAhead(reader.buffers[1-reader.counter%2])
	if err != nil {
		return nil, false, err
	}

	if reader.exhausted && len(reader.ahead) == 0 {
		return chunk, true, nil
	}

	return chunk, false, nil
}

func (reader *streamReader) readAhead(buffer []byte) error {
	read, err := io.ReadFull(reader.src, buffer)
	if err == nil {
		reader.ahead = buffer[:read]
		reader.exhausted = false

		return nil
	}

	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		reader.ahead = buffer[:read]
		reader.exhausted = true

		return nil
	}

	return fmt.Errorf("opening sealed data: reading: %w", err)
}
