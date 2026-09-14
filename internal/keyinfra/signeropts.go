package keyinfra

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"
)

// SignerHash is the one hash a key of this type signs with for these options, refusing options it does not sign
// with: Ed25519 signs the message itself without a context, and RSA signs a SHA-256, SHA-384 or SHA-512 digest with
// PKCS #1 v1.5.
func SignerHash(public crypto.PublicKey, digest []byte, opts crypto.SignerOpts) (crypto.Hash, error) {
	if opts == nil {
		return 0, errors.New("signing needs options naming the hash")
	}

	hash, err := hashOf(opts)
	if err != nil {
		return 0, err
	}

	switch public.(type) {
	case ed25519.PublicKey:
		return 0, checkEd25519Opts(hash, opts)

	case *rsa.PublicKey:
		return hash, checkRSAOpts(hash, digest, opts)

	default:
		return 0, fmt.Errorf("unsupported key type %T", public)
	}
}

// opts is the caller's own code, a nil pointer inside it or its HashFunc may panic
func hashOf(opts crypto.SignerOpts) (hash crypto.Hash, err error) {
	defer func() {
		recovered := recover()
		if recovered != nil {
			// %T only, %v would call the value's own methods, which may panic again
			err = fmt.Errorf("signer options panicked with a %T", recovered)
		}
	}()

	return opts.HashFunc(), nil
}

func checkEd25519Opts(hash crypto.Hash, opts crypto.SignerOpts) error {
	if hash != 0 {
		return fmt.Errorf("ed25519 signs the message itself, not a %s digest", hash)
	}

	options, isOptions := opts.(*ed25519.Options)
	if !isOptions {
		return nil
	}

	if options.Context != "" {
		return errors.New("ed25519 signs here without a context")
	}

	return nil
}

func checkRSAOpts(hash crypto.Hash, digest []byte, opts crypto.SignerOpts) error {
	_, isPSS := opts.(*rsa.PSSOptions)
	if isPSS {
		return errors.New("rsa keys sign pkcs1v15 here, not pss")
	}

	if !slices.Contains([]crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}, hash) {
		return fmt.Errorf("rsa keys sign no %s digest here", hash)
	}

	if len(digest) != hash.Size() {
		return fmt.Errorf("a %s digest is %d bytes, not %d", hash, hash.Size(), len(digest))
	}

	return nil
}
