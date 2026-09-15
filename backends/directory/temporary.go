package directory

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/The127/signr/internal/keyinfra"
)

const temporaryRandomBytes = 16

func temporaryFileName(file string) (string, error) {
	random := make([]byte, temporaryRandomBytes)
	_, err := rand.Read(random)
	if err != nil {
		return "", fmt.Errorf("drawing a temporary name for %s: %w", file, err)
	}

	return filepath.Join(filepath.Dir(file), "."+filepath.Base(file)+"."+hex.EncodeToString(random)), nil
}

func isTemporaryName(name string) bool {
	withoutDot, hidden := strings.CutPrefix(name, ".")
	if !hidden {
		return false
	}

	jwa, suffix, found := strings.Cut(withoutDot, ".pem.")
	if !found {
		return false
	}

	_, err := keyinfra.GetKeyStrategy(jwa)
	if err != nil {
		return false
	}

	if len(suffix) != hex.EncodedLen(temporaryRandomBytes) {
		return false
	}

	return strings.Trim(suffix, "0123456789abcdef") == ""
}
