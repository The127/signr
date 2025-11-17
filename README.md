# signr

A small but smart Go library for managing signing keys and performing digital signatures.

signr provides:
- A KeyManager abstraction for organizing keys into named groups.
- Pluggable backends (currently an in-memory backend) for storing and generating keys.
- A simple SigningKey interface for signing and verifying data.

## Installation

``` bash
go get github.com/The127/signr
```

If you want to use the in-memory backend:

``` bash
go get github.com/The127/signr/backends/memory
```

## Quick Start

The example below shows how to:
- Create a key manager with the in-memory backend.
- Lazily generate an EdDSA key in a named group.
- Sign and verify a message.

``` go
package main

import (
    "fmt"
    "time"

	"github.com/The127/signr"
	"github.com/The127/signr/backends/memory"
)

// Clock implements the memory backend's Clock interface using time.Now.
type Clock struct{}

func (c Clock) Now() time.Time {
    return time.Now()
}

func main() {
    // Initialize a KeyManager with the in-memory backend.
    km, err := signr.New(signr.Config{
        Backend: memory.Config{
            Clock: Clock{},
        },
    })
    if err != nil {
        panic(fmt.Errorf("failed to create key manager: %w", err))
    }

    // Get the "signing-key" group and an EdDSA key from it.
    // If no EdDSA key exists yet, it will be generated automatically.
    key, err := km.GetGroup("signing-key").GetKey("EdDSA")
    if err != nil {
        panic(fmt.Errorf("failed to get key: %w", err))
    }
    
    // Sign some data.
    msg := []byte("hello")
    sig, err := key.Sign(msg)
    if err != nil {
        panic(fmt.Errorf("failed to sign: %w", err))
    }
    
    // Print the signature as hex.
    fmt.Printf("signature: %x\n", sig)
    
    // Verify the signature.
    if err := key.Verify(msg, sig); err != nil {
        panic(fmt.Errorf("failed to verify: %w", err))
    }
    
    fmt.Println("ok")
}
```

Example output (actual signature will differ):
``` text
signature: 5d610e0ec5f902695a2582887845b3f49b7c447f484da63ea0842daf999fa8f8b6a104ce98d5de323070f9be771ac893097e2fe95058f15e5a61846ff81aea0e
ok
```


## Concepts

### Key Manager

The key manager is the main entry point:
- Organizes keys into groups (e.g. "signing-key", "refresh-tokens", etc.).
- Provides a high-level API to get keys by group and algorithm.

Typical usage:

``` go
km, err := signr.New(signr.Config{/* backend config */})
group := km.GetGroup("signing-key")
key, err := group.GetKey("EdDSA")
```

### Key Groups

A key group is a logical bucket of keys that belong together (for example, all keys used to sign access tokens).
You address keys within a group by JWA algorithm name (e.g. "EdDSA", "RS256").
The backend decides how keys are generated, stored, and rotated.

### Signing Keys

A SigningKey can:
- Sign data: Sign(data []byte) ([]byte, error)
- Verify signatures: Verify(data, signature []byte) error
- Expose metadata: algorithm name and key ID.

This is what you get back from GetKey.
 
## Backends

Backends are responsible for storing and generating keys.
They implement the concrete interactions with the underlying key storage system.

signr ships with the following backends:

### In-Memory Backend

The in-memory backend:
- Stores all key groups and keys in process memory.
- Lazily generates keys when GetKey is called and no active key exists for the requested algorithm.
- Uses an injected Clock to timestamp key creation (handy for testing or custom time sources).

Use it when:
- You want a simple setup for demos, tests, or local development.
- You don’t need keys to persist across process restarts.
 
## Running the Example

There is a simple example program under example/ which is similar to the quick-start snippet.

From the module root:
``` bash
cd example
go run .
```

You should see a hex-encoded signature followed by:
``` text
ok
```

 
## License

This project is licensed under the MIT license.
