package signr

import "crypto"

// PublicKey is the public half of one key version in a group, enough to verify what it signed.
type PublicKey struct {
	KeyID     string
	Algorithm string
	Key       crypto.PublicKey
}
