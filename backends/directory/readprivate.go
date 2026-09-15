package directory

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

// an RSA-4096 key file is about 3.3 KB
const maxKeyFileSize = 64 << 10

func readPrivateFile(root *os.Root, name string) ([]byte, error) {
	linked, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("inspecting %s: %w", name, err)
	}

	if !linked.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file but %s", name, linked.Mode().Type())
	}

	// without O_NONBLOCK, a FIFO swapped in after the Lstat blocks the open until something writes to it
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", name, err)
	}
	defer func() {
		_ = file.Close()
	}()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspecting %s: %w", name, err)
	}

	if !os.SameFile(linked, info) {
		return nil, fmt.Errorf("%s was replaced while it was opened", name)
	}

	if info.Size() > maxKeyFileSize {
		return nil, fmt.Errorf("%s is %d bytes, larger than any key file of %d bytes", name, info.Size(), maxKeyFileSize)
	}

	err = checkOwner(name, info)
	if err != nil {
		return nil, err
	}

	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has mode %#o, a private key must not be open to group or others", name, info.Mode().Perm())
	}

	content, err := io.ReadAll(io.LimitReader(file, maxKeyFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", name, err)
	}

	if len(content) > maxKeyFileSize {
		return nil, fmt.Errorf("%s grew past %d bytes while it was read", name, maxKeyFileSize)
	}

	return content, nil
}
