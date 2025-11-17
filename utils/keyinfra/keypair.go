package keyinfra

import (
	"crypto"
	"time"
)

// KeyPair represents a cryptographic key pair consisting of a public key, private key, key ID, and creation timestamp.
type KeyPair struct {
	publicKey  crypto.PublicKey
	privateKey crypto.PrivateKey
	kid        string
	createdAt  time.Time
}

// PrivateKey returns the private key of the KeyPair.
func (k *KeyPair) PrivateKey() crypto.PrivateKey {
	return k.privateKey
}

// PublicKey returns the public key associated with the KeyPair.
func (k *KeyPair) PublicKey() crypto.PublicKey {
	return k.publicKey
}

// Kid returns the key identifier (KID) associated with the KeyPair.
func (k *KeyPair) Kid() string {
	return k.kid
}

// CreatedAt returns the timestamp indicating when the KeyPair was created.
func (k *KeyPair) CreatedAt() time.Time {
	return k.createdAt
}
