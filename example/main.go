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
