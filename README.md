# signr

Backend agnostic key management for Go. A backend generates, holds and
rotates keys, callers address them by group and algorithm and get
something that signs. A private key never leaves its backend, so an HSM
or a TPM can stand behind the same interface as the in-memory default.

signr provides:

- A `KeyManager` that organizes keys into named groups.
- Pluggable backends that decide where keys live. The in-memory backend
  ships with the module.
- A `SigningKey` that signs and verifies, exposes its public key and
  key id, and hands out a `crypto.Signer` for the standard library's
  TLS, SSH and certificate APIs.
- A `jwt.SigningMethod` adapter for `github.com/golang-jwt/jwt/v5`.

## Installation

```bash
go get github.com/The127/signr
```

The in-memory backend lives in its own package:

```bash
go get github.com/The127/signr/backends/memory
```

## Quick start

```go
package main

import (
	"fmt"
	"time"

	"github.com/The127/signr"
	"github.com/The127/signr/backends/memory"
)

type clock struct{}

func (clock) Now() time.Time {
	return time.Now()
}

func main() {
	manager, err := signr.New(signr.Config{
		Backend: memory.Config{Clock: clock{}},
	})
	if err != nil {
		panic(err)
	}

	// The first call for an algorithm generates the key.
	key, err := manager.GetGroup("tokens").GetKey("EdDSA")
	if err != nil {
		panic(err)
	}

	signature, err := key.Sign([]byte("hello"))
	if err != nil {
		panic(err)
	}

	err = key.Verify([]byte("hello"), signature)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s signed by %s\n", key.Algorithm(), key.KeyID())
}
```

The same program is in `example/`.

## Concepts

### Key manager and groups

`signr.New` takes a backend configuration and returns the `KeyManager`.
`GetGroup(name)` names a bucket of keys that belong together, for
example every key that signs access tokens. Within a group a key is
addressed by its JWA algorithm name.

### Algorithms

`EdDSA` (Ed25519), `RS256`, `RS384` and `RS512` (RSA-4096 with PKCS #1
v1.5 over the named SHA-2 hash). An unknown name is an error, never a
panic.

### Signing keys

A `SigningKey` signs data and verifies signatures with the hashing the
algorithm prescribes, so a signature from `Sign` verifies with the
standard library directly. `Signer()` returns the key as a
`crypto.Signer` for `crypto/tls`, `golang.org/x/crypto/ssh` and
`crypto/x509`. `KeyID()` is the RFC 7638 JWK thumbprint of the public
key.

### Backends

A backend implements `signr.Backend` and `signr.BackendGroup` and owns
its keys entirely: generation, storage, and which key is active. Nothing
outside a backend sees private key material as bytes.

The in-memory backend keeps keys in process memory and generates a key
on the first `GetKey` for an algorithm in a group, under the group's
lock, so concurrent first callers share one key. Keys are gone when the
process ends. It takes a `Clock` so key creation times can be controlled
in tests. It does not rotate keys yet.

### JSON web tokens

`jwtmethod.NewJwtSigningMethod(key)` returns a `jwt.SigningMethod` that
signs with the key, for `jwt.NewWithClaims`. It only signs: verify a
token with the key's public key and the standard method for its
algorithm. Do not register it with `jwt.RegisterSigningMethod`.

## Development

`just setup` installs the git hooks, `just ci` runs everything the hooks
and the workflow run. See `CONTRIBUTING.md`.
