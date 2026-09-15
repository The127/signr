package directory

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/The127/signr"
)

// Config names the directory the backend keeps its keys in, as an absolute path no one but its owner may write.
type Config struct {
	Path string
}

// Create returns a backend that keeps its keys under the configured directory, refusing the directory the way ssh's
// StrictModes refuses a key, except that under go test the directories above it go unchecked.
func (config Config) Create() (signr.Backend, error) {
	if !filepath.IsAbs(config.Path) {
		return nil, fmt.Errorf("directory backend needs an absolute path, not %q", config.Path)
	}

	path, err := filepath.EvalSymlinks(config.Path)
	if err != nil {
		return nil, fmt.Errorf("resolving key directory: %w", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inspecting key directory: %w", err)
	}

	err = checkPrivateDirectory(path, info)
	if err != nil {
		return nil, err
	}

	err = checkParents(path)
	if err != nil {
		return nil, err
	}

	return &backend{
		path: path,
	}, nil
}
