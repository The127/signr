package main

import (
	"fmt"
	"time"

	"github.com/The127/signr"
	"github.com/The127/signr/backends/memory"
)

// Clock is a simple implementation of the memory backend's Clock interface.
// It just delegates to time.Now(). This is injected into the backend so that
// key generation and timestamps can be controlled or mocked in tests.
type Clock struct{}

// Now returns the current time. This satisfies memory.Clock.
func (c *Clock) Now() time.Time {
	return time.Now()
}

func main() {
	// Create a KeyManager using the in-memory backend.
	// The memory backend will store key groups and keys in memory only
	// (nothing is persisted to disk).
	km, err := signr.New(signr.Config{
		Backend: memory.Config{
			// Provide our Clock implementation so the backend
			// knows how to get the current time.
			Clock: &Clock{},
		},
	})
	if err != nil {
		// If backend creation fails for any reason, abort the program.
		panic(fmt.Errorf("failed to create key manager: %w", err))
	}

	// Get (or lazily create) a key group named "signing-key", and within that
	// group obtain the active key for the "EdDSA" algorithm.
	//
	// If no EdDSA key exists yet in this group, the memory backend will:
	//   - generate a new EdDSA key pair,
	//   - store it as the active key for "EdDSA",
	//   - and return it.
	key, err := km.GetGroup("signing-key").GetKey("EdDSA")
	if err != nil {
		panic(fmt.Errorf("failed to get key: %w", err))
	}

	// Sign the message "hello" with the retrieved EdDSA key.
	// The result is a binary signature.
	sig, err := key.Sign([]byte("hello"))
	if err != nil {
		panic(fmt.Errorf("failed to sign: %w", err))
	}

	// Print the signature in hexadecimal form so it’s human-readable.
	fmt.Printf("%x\n", sig)

	// Verify that the signature is valid for the same message "hello"
	// using the same key's public part.
	err = key.Verify([]byte("hello"), sig)
	if err != nil {
		// If verification fails, something is wrong (tampered data,
		// wrong key, etc.), so abort.
		panic(fmt.Errorf("failed to verify: %w", err))
	}

	// If we reach this point, signing and verification have succeeded.
	fmt.Println("ok")
}
