package ca

import (
	"fmt"
	"os"

	"github.com/veil-net/conflux/internal/paths"
)

// checkDir refuses a CA directory another account owns: whoever owns it can grant themselves
// the right to replace the CA's certificate, its key or its record of what it issued.
func checkDir(dir string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}

	if !st.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}

	if !paths.Trusted(dir) {
		return fmt.Errorf("%s belongs to another account, so it is not this account's CA to use", dir)
	}

	return nil
}
