package signr

// SealingBackendGroup is a BackendGroup that can also seal, a backend group without it cannot.
type SealingBackendGroup interface {
	// GetSealingKey returns the group's key for sealing data.
	GetSealingKey() (SealingKey, error)
}
