package main

import (
	"bytes"
	"fmt"
	"io"
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

	sign(manager.GetGroup("tokens"))
	seal(manager.GetGroup("tokens"))
}

func sign(group signr.KeyGroup) {
	// The first call for an algorithm generates the key.
	key, err := group.GetKey("EdDSA")
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

func seal(group signr.KeyGroup) {
	key, err := group.GetSealingKey("A256GCM")
	if err != nil {
		panic(err)
	}

	// Seal streams into any writer, a small value goes through a buffer.
	var sealed bytes.Buffer
	writer, err := key.Seal(&sealed, []byte("label"))
	if err != nil {
		panic(err)
	}
	_, err = writer.Write([]byte("secret"))
	if err != nil {
		panic(err)
	}
	err = writer.Close()
	if err != nil {
		panic(err)
	}
	sealedBytes := sealed.Len()

	// Open needs the same associated data, anything else is an error.
	reader, err := key.Open(&sealed, []byte("label"))
	if err != nil {
		panic(err)
	}
	opened, err := io.ReadAll(reader)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%d sealed bytes opened to %q\n", sealedBytes, opened)
}
