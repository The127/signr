package signr

// Config holds the configuration settings for initializing a cryptographic backend.
type Config struct {

	// Backend specifies the configuration for initializing and managing a cryptographic backend.
	Backend BackendConfig
}
