package signr

type BackendConfig interface {
	Create() (Backend, error)
}
