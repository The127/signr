package directory

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

var errAlreadyStored = errors.New("a key is already stored under that name")

func writeOnce(root *os.Root, name string, data []byte) error {
	temporary, err := temporaryFileName(name)
	if err != nil {
		return err
	}

	err = writeNewFile(root, temporary, data)
	if err != nil {
		return err
	}

	// Link fails when name exists, where Rename would replace a key already handed out.
	linkErr := root.Link(temporary, name)
	removeErr := root.Remove(temporary)

	if removeErr != nil {
		return errors.Join(linkErr, removeErr)
	}

	if errors.Is(linkErr, fs.ErrExist) {
		return errAlreadyStored
	}

	if linkErr != nil {
		return fmt.Errorf("linking %s: %w", name, linkErr)
	}

	return syncDirectory(root, filepath.Dir(name))
}

func writeNewFile(root *os.Root, name string, data []byte) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("creating %s: %w", name, err)
	}

	err = writeSyncAndClose(file, data)
	if err != nil {
		return errors.Join(err, root.Remove(name))
	}

	return nil
}

func writeSyncAndClose(file *os.File, data []byte) error {
	_, err := file.Write(data)
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("writing %s: %w", file.Name(), err)
	}

	err = file.Sync()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("syncing %s: %w", file.Name(), err)
	}

	err = file.Close()
	if err != nil {
		return fmt.Errorf("closing %s: %w", file.Name(), err)
	}

	return nil
}

func syncDirectory(root *os.Root, name string) error {
	directory, err := root.Open(name)
	if err != nil {
		return fmt.Errorf("opening %s: %w", name, err)
	}

	err = directory.Sync()
	if err != nil {
		_ = directory.Close()
		return fmt.Errorf("syncing %s: %w", name, err)
	}

	err = directory.Close()
	if err != nil {
		return fmt.Errorf("closing %s: %w", name, err)
	}

	return nil
}
