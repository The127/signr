package backendtest

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"sync/atomic"
)

// the embedded SignerOpts stays nil, so HashFunc panics
type panickingOpts struct {
	crypto.SignerOpts
}

type panickingError struct{}

func (panickingError) Error() string {
	panic(panickingError{})
}

type doublyPanickingOpts struct{}

func (doublyPanickingOpts) HashFunc() crypto.Hash {
	panic(panickingError{})
}

type changingOpts struct {
	calls atomic.Int32
	first crypto.Hash
	later crypto.Hash
}

func (opts *changingOpts) HashFunc() crypto.Hash {
	if opts.calls.Add(1) == 1 {
		return opts.first
	}

	return opts.later
}

func (s *Suite) TestASignerRefusesOptionsItsAlgorithmDoesNotSignInsteadOfPanicking() {
	message := []byte("hello")
	sha256Digest := sha256.Sum256(message)
	sha512Digest := sha512.Sum512(message)

	signers := map[string]crypto.Signer{}
	for _, algorithm := range []string{"EdDSA", "RS256"} {
		signer, err := s.newKey(algorithm).Signer()
		s.Require().NoError(err)
		signers[algorithm] = signer
	}

	cases := []struct {
		name      string
		algorithm string
		digest    []byte
		opts      crypto.SignerOpts
	}{
		{"EdDSA/no options", "EdDSA", message, nil},
		{"EdDSA/a SHA-256 digest", "EdDSA", sha256Digest[:], crypto.SHA256},
		{"EdDSA/a context", "EdDSA", message, &ed25519.Options{Context: "context"}},
		{"EdDSA/Ed25519ph", "EdDSA", sha512Digest[:], &ed25519.Options{Hash: crypto.SHA512}},
		{"EdDSA/a nil options pointer", "EdDSA", message, (*ed25519.Options)(nil)},
		{"EdDSA/options whose HashFunc panics", "EdDSA", message, panickingOpts{}},
		{"EdDSA/options that panic with an error whose Error panics", "EdDSA", message, doublyPanickingOpts{}},
		{"RS256/no options", "RS256", sha256Digest[:], nil},
		{"RS256/SHA-1", "RS256", make([]byte, 20), crypto.SHA1},
		{"RS256/no hash", "RS256", sha256Digest[:], crypto.Hash(0)},
		{"RS256/PSS", "RS256", sha256Digest[:], &rsa.PSSOptions{Hash: crypto.SHA256}},
		{"RS256/a nil PSS pointer", "RS256", sha256Digest[:], (*rsa.PSSOptions)(nil)},
		{"RS256/a digest of the wrong length", "RS256", message, crypto.SHA256},
		{"RS256/options whose HashFunc panics", "RS256", sha256Digest[:], panickingOpts{}},
	}

	for _, refused := range cases {
		s.Run(refused.name, func() {
			// arrange
			signer := signers[refused.algorithm]

			// act
			_, err := signer.Sign(rand.Reader, refused.digest, refused.opts)

			// assert
			s.Error(err)
		})
	}
}

func (s *Suite) TestOptionsThatChangeTheirAnswerCannotSlipPastTheSignersCheck() {
	s.Run("RS256", func() {
		// arrange
		signer, err := s.newKey("RS256").Signer()
		s.Require().NoError(err)
		digest := sha256.Sum256([]byte("hello"))
		opts := &changingOpts{first: crypto.SHA256, later: 0}

		// act
		signature, err := signer.Sign(rand.Reader, digest[:], opts)

		// assert
		s.Require().NoError(err)
		s.NoError(rsa.VerifyPKCS1v15(signer.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], signature))
	})

	s.Run("EdDSA", func() {
		// arrange
		signer, err := s.newKey("EdDSA").Signer()
		s.Require().NoError(err)
		message := make([]byte, sha512.Size)
		opts := &changingOpts{first: 0, later: crypto.SHA512}

		// act
		signature, err := signer.Sign(rand.Reader, message, opts)

		// assert
		s.Require().NoError(err)
		s.True(ed25519.Verify(signer.Public().(ed25519.PublicKey), message, signature))
	})
}
