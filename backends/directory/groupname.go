package directory

import (
	"errors"
	"fmt"
	"strings"
)

const safeGroupNameCharacters = "abcdefghijklmnopqrstuvwxyz0123456789_-"

const maxGroupNameLength = 255

func checkGroupName(name string) error {
	if name == "" {
		return errors.New(`group name "" is empty`)
	}

	if len(name) > maxGroupNameLength {
		return fmt.Errorf("group name %q is longer than %d characters", name, maxGroupNameLength)
	}

	for _, character := range name {
		if !strings.ContainsRune(safeGroupNameCharacters, character) {
			return fmt.Errorf("group name %q has %q outside [a-z0-9_-]", name, character)
		}
	}

	return nil
}
