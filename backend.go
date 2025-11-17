package signr

// Backend defines an interface for managing and retrieving signing key groups.
// It provides methods for accessing or creating grouped keys used in cryptographic operations.
type Backend interface {

	// GetGroup retrieves a BackendGroup by its name with the specified options, creating it if AutoCreate is true in options.
	GetGroup(name string, opts GroupOptions) (BackendGroup, error)
}
