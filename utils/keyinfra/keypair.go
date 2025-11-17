package keyinfra

import (
	"crypto"
	"time"
)

type KeyPair struct {
	publicKey  crypto.PublicKey
	privateKey crypto.PrivateKey
	kid        string
	createdAt  time.Time
}

func (k *KeyPair) PrivateKey() crypto.PrivateKey {
	return k.privateKey
}

func (k *KeyPair) PublicKey() crypto.PublicKey {
	return k.publicKey
}

func (k *KeyPair) Kid() string {
	return k.kid
}

func (k *KeyPair) CreatedAt() time.Time {
	return k.createdAt
}
