package main

import (
	"fmt"
	"time"

	"github.com/The127/signr"
	"github.com/The127/signr/backends/memory"
)

type Clock struct{}

func (c Clock) Now() time.Time {
	return time.Now()
}

func main() {
	km, err := signr.New(signr.Config{
		Backend: memory.Config{
			Clock: Clock{},
		},
	})
	if err != nil {
		panic(fmt.Errorf("failed to create key manager: %w", err))
	}

	key, err := km.GetGroup("oci-token-signing").GetKey("EdDSA")
	if err != nil {
		panic(fmt.Errorf("failed to get key: %w", err))
	}

	sig, err := key.Sign([]byte("hello"))
	if err != nil {
		panic(fmt.Errorf("failed to sign: %w", err))
	}

	fmt.Printf("%x\n", sig)

	err = key.Verify([]byte("hello"), sig)
	if err != nil {
		panic(fmt.Errorf("failed to verify: %w", err))
	}

	fmt.Println("ok")
}
