package signr

type BackendGroup interface {
	GetKey(jwa string) (SigningKey, error)
}
