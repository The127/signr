package openbao

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/The127/signr/internal/keyinfra"
)

var transitHashNames = map[crypto.Hash]string{
	crypto.SHA256: "sha2-256",
	crypto.SHA384: "sha2-384",
	crypto.SHA512: "sha2-512",
}

type transitSigner struct {
	transit transit
	name    string
	version int
	public  keyinfra.KeptPublicKey
}

// Public is a copy of the public half of the key version the signer signs with, which the caller owns.
func (signer transitSigner) Public() crypto.PublicKey {
	return signer.public.Copy()
}

// Sign asks Transit to sign the digest with the signer's key version, refusing options Transit would not honour.
// Transit draws its own randomness.
func (signer transitSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	request, err := signer.signRequest(digest, opts)
	if err != nil {
		return nil, err
	}

	response, err := signer.transit.sign(signer.name, request)
	if err != nil {
		return nil, err
	}

	encoded, found := strings.CutPrefix(response.Data.Signature, "vault:v"+strconv.Itoa(signer.version)+":")
	if !found {
		return nil, fmt.Errorf("transit signed with another key version than %d", signer.version)
	}

	signature, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding the transit signature: %w", err)
	}

	// whatever answers at the address is not trusted to have signed with the key it named
	err = signer.verify(digest, opts, signature)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (signer transitSigner) verify(digest []byte, opts crypto.SignerOpts, signature []byte) error {
	switch public := signer.public.Copy().(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(public, digest, signature) {
			return errors.New("transit answered a signature the key does not verify")
		}

		return nil

	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(public, opts.HashFunc(), digest, signature)
		if err != nil {
			return fmt.Errorf("transit answered a signature the key does not verify: %w", err)
		}

		return nil

	default:
		return fmt.Errorf("unsupported key type %T", public)
	}
}

func (signer transitSigner) signRequest(digest []byte, opts crypto.SignerOpts) (signRequest, error) {
	if opts == nil {
		return signRequest{}, errors.New("signing needs options naming the hash")
	}

	switch public := signer.public.Copy().(type) {
	case ed25519.PublicKey:
		if opts.HashFunc() != 0 {
			return signRequest{}, fmt.Errorf("ed25519 signs the message itself, not a %s digest", opts.HashFunc())
		}

		if contextOf(opts) != "" {
			return signRequest{}, errors.New("transit signs plain ed25519, without a context")
		}

		return signRequest{
			Input:      base64.StdEncoding.EncodeToString(digest),
			KeyVersion: signer.version,
		}, nil

	case *rsa.PublicKey:
		_, isPSS := opts.(*rsa.PSSOptions)
		if isPSS {
			return signRequest{}, errors.New("transit rsa keys sign pkcs1v15 here, not pss")
		}

		hashName, found := transitHashNames[opts.HashFunc()]
		if !found {
			return signRequest{}, fmt.Errorf("transit rsa keys sign no %s digest here", opts.HashFunc())
		}

		if len(digest) != opts.HashFunc().Size() {
			return signRequest{}, fmt.Errorf("a %s digest is %d bytes, not %d", opts.HashFunc(), opts.HashFunc().Size(), len(digest))
		}

		return signRequest{
			Input:              base64.StdEncoding.EncodeToString(digest),
			KeyVersion:         signer.version,
			Prehashed:          true,
			HashAlgorithm:      hashName,
			SignatureAlgorithm: "pkcs1v15",
		}, nil

	default:
		return signRequest{}, fmt.Errorf("unsupported key type %T", public)
	}
}

func contextOf(opts crypto.SignerOpts) string {
	options, isOptions := opts.(*ed25519.Options)
	if !isOptions {
		return ""
	}

	return options.Context
}
