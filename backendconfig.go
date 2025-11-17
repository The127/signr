package signr

// BackendConfig defines an interface for creating a cryptographic backend that manages signing key groups.
type BackendConfig interface {

	// Create initializes and returns a new Backend instance or an error if the creation fails.
	Create() (Backend, error)
}
