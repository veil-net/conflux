//go:build !windows

package ca

import (
	"os"
	"strings"
	"testing"
)

// TestADirectoryOthersMayWriteIsRefused: a CA whose directory became group-writable is not
// opened; one made in an empty 0755 directory is narrowed to 0700.
func TestADirectoryOthersMayWriteIsRefused(t *testing.T) {
	c := initCA(t, false)
	c.Close()

	if st, _ := os.Stat(c.Dir); st.Mode().Perm() != 0o700 {
		t.Errorf("the CA directory is %v", st.Mode().Perm())
	}

	if err := os.Chmod(c.Dir, 0o770); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(c.Dir); err == nil || !strings.Contains(err.Error(), "writable by others") {
		t.Errorf("a group-writable CA: %v", err)
	}
}
