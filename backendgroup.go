package signr

// BackendGroup provides an interface for managing and retrieving cryptographic signing keys grouped by algorithm names.
// It includes methods to retrieve or generate the appropriate signing key for a given algorithm.
type BackendGroup interface {

	// GetKey retrieves the active signing key for the specified JWA algorithm or generates a new one if none exists.
	GetKey(jwa string) (SigningKey, error)
}
