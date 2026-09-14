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

// keyinfra.OpaqueSigner checks opts before this is reached, it is the only way in
func (signer transitSigner) signRequest(digest []byte, opts crypto.SignerOpts) (signRequest, error) {
	switch public := signer.public.Copy().(type) {
	case ed25519.PublicKey:
		return signRequest{
			Input:      base64.StdEncoding.EncodeToString(digest),
			KeyVersion: signer.version,
		}, nil

	case *rsa.PublicKey:
		hashName, found := transitHashNames[opts.HashFunc()]
		if !found {
			return signRequest{}, fmt.Errorf("transit rsa keys sign no %s digest here", opts.HashFunc())
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
