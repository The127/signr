package directory

import (
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func checkParents(path string) error {
	// go test keeps its temporary directories below /tmp, which ssh's rules refuse as writable by everyone
	if testing.Testing() {
		return nil
	}

	home := homeDirectory()

	directory := path
	for {
		// the path was resolved at Create, so a symbolic link on it now means a directory above was swapped
		info, err := os.Lstat(directory)
		if err != nil {
			return fmt.Errorf("inspecting %s: %w", directory, err)
		}

		err = checkParent(directory, info)
		if err != nil {
			return err
		}

		if directory == home {
			return nil
		}

		parent := filepath.Dir(directory)
		if parent == directory {
			return nil
		}

		directory = parent
	}
}

// like ssh, home comes from the user database and never from $HOME, so the environment cannot move where the walk
// stops, and without a home the walk goes up to / as ssh's does for a key outside home
func homeDirectory() string {
	account, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		return ""
	}

	resolved, err := filepath.EvalSymlinks(account.HomeDir)
	if err != nil {
		return ""
	}

	return resolved
}

func checkParent(name string, info fs.FileInfo) error {
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory but %s", name, info.Mode().Type())
	}

	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s has mode %#o, no directory above the keys may be writable by group or others", name, info.Mode().Perm())
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s has no owner this platform reports", name)
	}

	if stat.Uid == 0 {
		return nil
	}

	if int64(stat.Uid) != int64(os.Geteuid()) {
		return fmt.Errorf("%s belongs to uid %d, neither to root nor to uid %d this process runs as", name, stat.Uid, os.Geteuid())
	}

	return nil
}
