//go:build !windows

package ca

import (
	"fmt"
	"os"
	"syscall"
)

// checkDir refuses a CA directory another account owns, or one others may write: whoever can
// write it can replace the CA's certificate, its key or its record of what it issued.
func checkDir(dir string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}

	switch {
	case !st.IsDir():
		return fmt.Errorf("%s is not a directory", dir)
	case st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()):
		return fmt.Errorf("%s belongs to another account, so it is not this account's CA to use", dir)
	case st.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("%s is writable by others (%v), so its CA could have been changed by them: "+
			"make it 0700 (chmod 700 %s) if nobody did", dir, st.Mode().Perm(), dir)
	}

	return nil
}
