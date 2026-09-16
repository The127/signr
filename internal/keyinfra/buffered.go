package keyinfra

import (
	"bytes"
	"errors"
	"io"
)

// SealBuffered returns a writer that collects everything written and seals it into dst as one message on Close.
func SealBuffered(dst io.Writer, seal func(plaintext []byte) ([]byte, error)) io.WriteCloser {
	return &bufferedWriter{
		dst:  dst,
		seal: seal,
	}
}

// OpenBuffered reads all of src as one sealed message and returns a reader of its plaintext.
func OpenBuffered(src io.Reader, open func(sealed []byte) ([]byte, error)) (io.Reader, error) {
	sealed, err := io.ReadAll(src)
	if err != nil {
		return nil, err
	}

	plaintext, err := open(sealed)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(plaintext), nil
}

type bufferedWriter struct {
	dst       io.Writer
	seal      func(plaintext []byte) ([]byte, error)
	plaintext bytes.Buffer
	closed    bool
}

func (writer *bufferedWriter) Write(data []byte) (int, error) {
	if writer.closed {
		return 0, errors.New("sealing data: write after close")
	}

	return writer.plaintext.Write(data)
}

func (writer *bufferedWriter) Close() error {
	if writer.closed {
		return nil
	}

	writer.closed = true

	sealed, err := writer.seal(writer.plaintext.Bytes())
	if err != nil {
		return err
	}

	_, err = writer.dst.Write(sealed)

	return err
}
