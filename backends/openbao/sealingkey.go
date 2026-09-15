package openbao

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/The127/signr"
)

const sealingAlgorithm = "AES-256-GCM"

const sealingKeyType = "aes256-gcm96"

// GetSealingKey returns the group's key for sealing with the algorithm, creating the key in Transit on the first
// call.
func (group *keyGroup) GetSealingKey(algorithm string) (signr.SealingKey, error) {
	if algorithm != sealingAlgorithm {
		return nil, fmt.Errorf("unsupported algorithm %q", algorithm)
	}

	name := keyName(group.name, algorithm)

	keyType, err := group.transit.createSealingKey(name, sealingKeyType)
	if err != nil {
		return nil, err
	}

	if keyType != sealingKeyType {
		return nil, fmt.Errorf("transit key %s: transit holds it as %s, not %s", name, keyType, sealingKeyType)
	}

	return &sealingKey{
		transit: group.transit,
		name:    name,
	}, nil
}

type sealingKey struct {
	transit transit
	name    string
}

// Seal asks Transit to seal the plaintext for Open with the same associated data.
func (key *sealingKey) Seal(plaintext []byte, associatedData []byte) ([]byte, error) {
	response, err := key.transit.encrypt(key.name, encryptRequest{
		Plaintext:      base64.StdEncoding.EncodeToString(plaintext),
		AssociatedData: base64.StdEncoding.EncodeToString(associatedData),
	})
	if err != nil {
		return nil, err
	}

	return []byte(response.Data.Ciphertext), nil
}

// Open asks Transit for the plaintext of a ciphertext Seal produced with the same associated data.
func (key *sealingKey) Open(ciphertext []byte, associatedData []byte) ([]byte, error) {
	sealed := string(ciphertext)

	err := checkSpelling(sealed)
	if err != nil {
		return nil, err
	}

	response, err := key.transit.decrypt(key.name, decryptRequest{
		Ciphertext:     sealed,
		AssociatedData: base64.StdEncoding.EncodeToString(associatedData),
	})
	if err != nil {
		return nil, err
	}

	plaintext, err := base64.StdEncoding.DecodeString(response.Data.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("decoding the transit plaintext: %w", err)
	}

	return plaintext, nil
}

// Transit parses sealed data leniently, so another spelling of the same ciphertext would open although its bytes changed
func checkSpelling(sealed string) error {
	rest, found := strings.CutPrefix(sealed, "vault:v")
	if !found {
		return errors.New("sealed data does not start with vault:v")
	}

	version, payload, found := strings.Cut(rest, ":")
	if !found {
		return errors.New("sealed data names no key version")
	}

	number, err := strconv.Atoi(version)
	if err != nil {
		return fmt.Errorf("sealed data names key version %q: %w", version, err)
	}

	if number < 1 {
		return fmt.Errorf("sealed data names key version %d, versions start at 1", number)
	}

	if strconv.Itoa(number) != version {
		return fmt.Errorf("sealed data spells key version %d as %q", number, version)
	}

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return fmt.Errorf("sealed data is not base64: %w", err)
	}

	// even strict decoding skips newlines, only a round trip leaves one spelling
	if base64.StdEncoding.EncodeToString(decoded) != payload {
		return errors.New("sealed data is not canonical base64")
	}

	return nil
}
