package directory

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/The127/signr"
	"github.com/The127/signr/internal/keyinfra"
)

type keyGroup struct {
	directory string
	name      string
}

// GetKey returns the key the group keeps for the algorithm, generating and storing one on the first call.
func (group *keyGroup) GetKey(jwa string) (signr.SigningKey, error) {
	keyStrategy, err := keyinfra.GetKeyStrategy(jwa)
	if err != nil {
		return nil, err
	}

	err = checkParents(group.directory)
	if err != nil {
		return nil, err
	}

	root, err := os.OpenRoot(group.directory)
	if err != nil {
		return nil, fmt.Errorf("opening key directory: %w", err)
	}
	defer func() {
		_ = root.Close()
	}()

	info, err := root.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("inspecting key directory: %w", err)
	}

	err = checkPrivateDirectory(group.directory, info)
	if err != nil {
		return nil, err
	}

	keys, err := openGroupDirectory(root, group.name)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = keys.Close()
	}()

	key, err := readOrGenerate(keys, keyStrategy, jwa+".pem")
	if err != nil {
		return nil, fmt.Errorf("group %s: %w", group.name, err)
	}

	// another process may have stored the key without its directory sync reaching the disk yet, and a handed-out
	// key must outlive a crash
	err = syncDirectory(keys, ".")
	if err != nil {
		return nil, err
	}

	err = syncDirectory(root, ".")
	if err != nil {
		return nil, err
	}

	return key, nil
}

func readOrGenerate(keys *os.Root, keyStrategy keyinfra.KeyAlgorithmStrategy, file string) (signr.SigningKey, error) {
	key, err := readKey(keys, keyStrategy, file)
	if errors.Is(err, fs.ErrNotExist) {
		return generate(keys, keyStrategy, file)
	}

	if err != nil {
		return nil, err
	}

	return key, nil
}

func generate(keys *os.Root, keyStrategy keyinfra.KeyAlgorithmStrategy, file string) (signr.SigningKey, error) {
	keyPair, err := keyStrategy.Generate(time.Now())
	if err != nil {
		return nil, fmt.Errorf("generating key pair: %w", err)
	}

	serialized, err := keyStrategy.Export(keyPair.PrivateKey())
	if err != nil {
		return nil, fmt.Errorf("exporting key: %w", err)
	}

	err = writeOnce(keys, file, []byte(serialized))
	if errors.Is(err, errAlreadyStored) {
		return readKey(keys, keyStrategy, file)
	}

	if err != nil {
		return nil, fmt.Errorf("storing key: %w", err)
	}

	return signingKey{
		kid: keyPair.Kid(),
	}, nil
}

func readKey(keys *os.Root, keyStrategy keyinfra.KeyAlgorithmStrategy, file string) (signr.SigningKey, error) {
	serialized, err := readPrivateFile(keys, file)
	if err != nil {
		return nil, err
	}

	_, publicKey, err := keyStrategy.Import(string(serialized))
	if err != nil {
		return nil, fmt.Errorf("importing %s: %w", file, err)
	}

	kid, err := keyinfra.KeyID(publicKey)
	if err != nil {
		return nil, fmt.Errorf("computing the key id of %s: %w", file, err)
	}

	return signingKey{
		kid: kid,
	}, nil
}

// PublicKeys lists nothing yet.
func (group *keyGroup) PublicKeys() ([]signr.PublicKey, error) {
	return nil, errors.New("directory backend cannot list public keys yet")
}
