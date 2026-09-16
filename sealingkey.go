package signr

import "io"

// SealingKey seals data so that only Open with the same key and the same associated data recovers it.
type SealingKey interface {
	// Seal returns a writer that seals what is written to it into dst for Open with the same associated data, and
	// Close finishes the sealed data.
	Seal(dst io.Writer, associatedData []byte) (io.WriteCloser, error)

	// Open returns a reader of the plaintext of sealed data Seal produced with the same associated data, and a
	// read error means nothing read so far can be trusted.
	Open(src io.Reader, associatedData []byte) (io.Reader, error)
}
