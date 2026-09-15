package signr

// SealingKey seals data so that only Open with the same key recovers it.
type SealingKey interface {
	// Seal returns the plaintext sealed for Open.
	Seal(plaintext []byte) ([]byte, error)

	// Open returns the plaintext of a ciphertext Seal produced.
	Open(ciphertext []byte) ([]byte, error)
}
