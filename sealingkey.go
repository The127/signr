package signr

// SealingKey seals data so that only Open with the same key and the same associated data recovers it.
type SealingKey interface {
	// Seal returns the plaintext sealed for Open with the same associated data.
	Seal(plaintext []byte, associatedData []byte) ([]byte, error)

	// Open returns the plaintext of a ciphertext Seal produced with the same associated data.
	Open(ciphertext []byte, associatedData []byte) ([]byte, error)
}
