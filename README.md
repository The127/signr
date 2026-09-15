# signr

Backend agnostic key management for Go. A backend generates, holds and
rotates keys, callers address them by group and algorithm and get
something that signs. A private key never leaves its backend, so an HSM
or a TPM can stand behind the same interface as the in-memory default.

signr provides:

- A `KeyManager` that organizes keys into named groups.
- Pluggable backends that decide where keys live. An in-memory backend,
  an OpenBao Transit backend and a directory backend ship with the
  module.
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
example every key that signs access tokens. Within a group a signing
key is addressed by its JWA algorithm name and the sealing key by
`AES-256-GCM`.

### Algorithms

Signing: `EdDSA` (Ed25519), `RS256`, `RS384` and `RS512` (RSA-4096 with
PKCS #1 v1.5 over the named SHA-2 hash). Sealing: `AES-256-GCM`. The
sealing name is signr's own and not a JWA name, because the sealed
format depends on the backend. An unknown name is an error, never a panic.

### Signing keys

A `SigningKey` signs data and verifies signatures with the hashing the
algorithm prescribes, so a signature from `Sign` verifies with the
standard library directly. `Signer()` returns the key as a
`crypto.Signer` for `crypto/tls`, `golang.org/x/crypto/ssh` and
`crypto/x509`. It signs only what the key's algorithm prescribes:
Ed25519 over the message itself, RSA with PKCS #1 v1.5 over SHA-256,
SHA-384 or SHA-512 and never PSS, so an RSA key serves TLS 1.2 but not
TLS 1.3. `PublicKey()` and a signer's `Public()` hand out a copy the
caller owns. `KeyID()` is the RFC 7638 JWK thumbprint of the public
key.

### Sealing keys

`GetSealingKey("AES-256-GCM")` returns the group's `SealingKey`.
`Seal(plaintext, associatedData)` encrypts, and
`Open(ciphertext, associatedData)` returns the plaintext only for bytes
this group's key sealed, unaltered, with the same associated data.
Anything else is an error. The associated data is a value the caller
chooses per seal and passes again to open, like a login password, and
`nil` means none. It is not a secret. The backend's key protects the
data, so the associated data adds nothing if that key leaks.

The memory and directory backends seal as a compact JWE (RFC 7516) with
`dir` and `A256GCM`, so any JOSE library opens a sealed value with the
key. Associated data that is not empty travels base64url-encoded in the
protected header `aad`, readable by anyone who sees the sealed value.
`Open` accepts only the exact shape `Seal` writes, before any key work:
five parts in canonical base64url, no encrypted key, a 16-byte tag, and
a header of `alg`, `enc` and `aad` spelled the one way `Seal` spells
it.

### Backends

A backend implements `signr.Backend` and `signr.BackendGroup` and owns
its keys entirely: generation, storage, and which key is active. Nothing
outside a backend sees private key material as bytes.

The in-memory backend keeps keys in process memory and generates a key
on the first `GetKey` for an algorithm in a group, under the group's
lock, so concurrent first callers share one key. Keys are gone when the
process ends, so data it sealed cannot be opened after a restart. It needs a `Clock` so key creation times can be controlled
in tests. It does not rotate keys yet.

The OpenBao backend keeps keys in a Transit mount. OpenBao generates
every key and signs with it, the backend only ever sees public keys and
signatures. The first `GetKey` for an algorithm creates the Transit key
`<group>-<algorithm>` as `ed25519` or `rsa-4096`, and a key Transit
already holds under that name as another type or size is refused. A
signing key and its `Signer()` ask Transit for every signature, pinned
to the key version `GetKey` returned, and check it against that
version's public key before handing it out.
`PublicKeys` lists every version Transit still verifies with. The config
takes a `TokenSource` that is asked before every request, `StaticToken`
answers a fixed token. Redirects are not followed, so the token never
travels to another host. Group names are letters, digits, `_` and `-`.
The first `GetSealingKey` creates the Transit key `<group>-AES-256-GCM`
as `aes256-gcm96`, and a key Transit holds under that name as another
type is refused. Transit seals and opens, so every `Seal` and `Open` is
one request and the plaintext travels to OpenBao. Sealed data is
Transit's `vault:v<version>:<base64>` text, and `Open` refuses base64
that is not in its one canonical form.

The directory backend keeps each key as a PEM file at
`<path>/<group>/<algorithm>.pem`, so keys survive a restart. The path
must be absolute. The backend refuses the directory the way ssh's
StrictModes refuses a key file. The key directory and its group
directories must belong to the process, every directory above them up
to the home directory from the user database must belong to root or the
process, and none of them may be writable by group or others. Key files
must be private regular files owned by the process. Under `go test` the
directories above the key directory go unchecked, so `t.TempDir()`
works. A key is written once, through a temp file linked into place,
and synced before it is handed out, so concurrent first callers across
processes share one key. `PublicKeys` lists every signing key file,
checks the sealing key file `AES-256-GCM.pem` the same way without
listing it, and refuses anything else it finds in a group directory.
Losing `AES-256-GCM.pem` loses everything sealed with it, so back it up
with the sealed data. Group names are lowercase
letters, digits, `_` and `-`. The backend runs on Unix only.

### JSON web tokens

`jwtmethod.NewJwtSigningMethod(key)` returns a `jwt.SigningMethod` that
signs with the key, for `jwt.NewWithClaims`. It only signs: verify a
token with the key's public key and the standard method for its
algorithm. Do not register it with `jwt.RegisterSigningMethod`.

## Development

`just setup` installs the git hooks, `just ci` runs everything the hooks
and the workflow run. `just test-openbao` runs the OpenBao backend's
contract against a throwaway OpenBao container and needs podman. See
`CONTRIBUTING.md`.
