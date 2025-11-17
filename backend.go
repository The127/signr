package signr

type Backend interface {
	GetGroup(name string, opts GroupOptions) (BackendGroup, error)
}
