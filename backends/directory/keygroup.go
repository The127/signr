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

	root, err := openKeyDirectory(group.directory)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = root.Close()
	}()

	keys, err := openGroupDirectory(root, group.name)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = keys.Close()
	}()

	key, err := readOrGenerate(keys, keyStrategy, jwa)
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

func readOrGenerate(keys *os.Root, keyStrategy keyinfra.KeyAlgorithmStrategy, jwa string) (signr.SigningKey, error) {
	key, err := readKey(keys, keyStrategy, jwa)
	if errors.Is(err, fs.ErrNotExist) {
		return generate(keys, keyStrategy, jwa)
	}

	if err != nil {
		return nil, err
	}

	return key, nil
}

func generate(keys *os.Root, keyStrategy keyinfra.KeyAlgorithmStrategy, jwa string) (signr.SigningKey, error) {
	keyPair, err := keyStrategy.Generate(time.Now())
	if err != nil {
		return nil, fmt.Errorf("generating key pair: %w", err)
	}

	serialized, err := keyStrategy.Export(keyPair.PrivateKey())
	if err != nil {
		return nil, fmt.Errorf("exporting key: %w", err)
	}

	err = writeOnce(keys, keyFile(jwa), []byte(serialized))
	if errors.Is(err, errAlreadyStored) {
		return readKey(keys, keyStrategy, jwa)
	}

	if err != nil {
		return nil, fmt.Errorf("storing key: %w", err)
	}

	return newSigningKey(keyPair.PrivateKey(), keyPair.Kid(), jwa, keyStrategy.Hash())
}

func readKey(keys *os.Root, keyStrategy keyinfra.KeyAlgorithmStrategy, jwa string) (signr.SigningKey, error) {
	file := keyFile(jwa)

	serialized, err := readPrivateFile(keys, file)
	if err != nil {
		return nil, err
	}

	privateKey, publicKey, err := keyStrategy.Import(string(serialized))
	if err != nil {
		return nil, fmt.Errorf("importing %s: %w", file, err)
	}

	kid, err := keyinfra.KeyID(publicKey)
	if err != nil {
		return nil, fmt.Errorf("computing the key id of %s: %w", file, err)
	}

	return newSigningKey(privateKey, kid, jwa, keyStrategy.Hash())
}

func keyFile(jwa string) string {
	return jwa + ".pem"
}
