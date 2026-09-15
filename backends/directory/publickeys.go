package directory

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/The127/signr"
	"github.com/The127/signr/internal/keyinfra"
)

// PublicKeys lists the public half of every key the group stores, generating none and refusing anything else found
// in the group's directory.
func (group *keyGroup) PublicKeys() ([]signr.PublicKey, error) {
	root, err := openKeyDirectory(group.directory)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = root.Close()
	}()

	keys, err := openExistingGroupDirectory(root, group.name)
	if errors.Is(err, fs.ErrNotExist) {
		return []signr.PublicKey{}, nil
	}

	if err != nil {
		return nil, err
	}
	defer func() {
		_ = keys.Close()
	}()

	names, err := listDirectory(keys)
	if err != nil {
		return nil, err
	}

	publicKeys := []signr.PublicKey{}
	for _, name := range names {
		leftover, err := isLeftoverTemporary(keys, name)
		if err != nil {
			return nil, fmt.Errorf("group %s: %w", group.name, err)
		}

		if leftover {
			continue
		}

		if name == keyFile(sealingAlgorithm) {
			_, err := readSealer(keys, name)
			if err != nil {
				return nil, fmt.Errorf("group %s: %w", group.name, err)
			}

			continue
		}

		publicKey, err := readPublicKey(keys, name)
		if err != nil {
			return nil, fmt.Errorf("group %s: %w", group.name, err)
		}

		publicKeys = append(publicKeys, publicKey)
	}

	return publicKeys, nil
}

func listDirectory(directory *os.Root) ([]string, error) {
	file, err := directory.Open(".")
	if err != nil {
		return nil, fmt.Errorf("opening group directory: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	names, err := file.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("listing group directory: %w", err)
	}

	return names, nil
}

// writeOnce leaves its temporary file behind only when the process dies between creating and removing it
func isLeftoverTemporary(keys *os.Root, name string) (bool, error) {
	if !isTemporaryName(name) {
		return false, nil
	}

	info, err := keys.Lstat(name)
	// a concurrent writeOnce removed its temporary file after the listing saw it
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}

	if err != nil {
		return false, fmt.Errorf("inspecting %s: %w", name, err)
	}

	return info.Mode().IsRegular(), nil
}

func readPublicKey(keys *os.Root, name string) (signr.PublicKey, error) {
	jwa, found := strings.CutSuffix(name, ".pem")
	if !found {
		return signr.PublicKey{}, fmt.Errorf("%s is not a key file", name)
	}

	keyStrategy, err := keyinfra.GetKeyStrategy(jwa)
	if err != nil {
		return signr.PublicKey{}, fmt.Errorf("%s: %w", name, err)
	}

	key, err := readKey(keys, keyStrategy, jwa)
	if err != nil {
		return signr.PublicKey{}, err
	}

	publicKey, err := key.PublicKey()
	if err != nil {
		return signr.PublicKey{}, fmt.Errorf("%s: %w", name, err)
	}

	return signr.PublicKey{
		KeyID:     key.KeyID(),
		Algorithm: jwa,
		Key:       publicKey,
	}, nil
}
