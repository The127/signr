package directory

import (
	"fmt"
	"io/fs"
	"os"
)

func checkPrivateDirectory(name string, info fs.FileInfo) error {
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", name)
	}

	err := checkOwner(name, info)
	if err != nil {
		return err
	}

	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s has mode %#o, a key directory must not be writable by group or others", name, info.Mode().Perm())
	}

	return nil
}

func openGroupDirectory(root *os.Root, name string) (*os.Root, error) {
	err := root.MkdirAll(name, 0o700)
	if err != nil {
		return nil, fmt.Errorf("creating %s: %w", name, err)
	}

	linked, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("inspecting %s: %w", name, err)
	}

	if !linked.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", name)
	}

	directory, err := root.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", name, err)
	}

	opened, err := directory.Stat(".")
	if err != nil {
		_ = directory.Close()
		return nil, fmt.Errorf("inspecting %s: %w", name, err)
	}

	if !os.SameFile(linked, opened) {
		_ = directory.Close()
		return nil, fmt.Errorf("%s was replaced while it was opened", name)
	}

	err = checkPrivateDirectory(name, opened)
	if err != nil {
		_ = directory.Close()
		return nil, err
	}

	return directory, nil
}
