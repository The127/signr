package directory

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

func checkOwner(name string, info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s has no owner this platform reports", name)
	}

	if int64(stat.Uid) != int64(os.Geteuid()) {
		return fmt.Errorf("%s belongs to uid %d, not to uid %d this process runs as", name, stat.Uid, os.Geteuid())
	}

	return nil
}
