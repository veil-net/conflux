//go:build !windows

package paths

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEphemeralPassesOverARootAnotherAccountMade: /tmp lets anybody make the name an
// ephemeral run's root would have, and one Foreign refuses -- another account's, or one another
// account may write -- is passed over for the next candidate rather than taken, or none taken.
func TestEphemeralPassesOverARootAnotherAccountMade(t *testing.T) {
	theirs := filepath.Join(t.TempDir(), "conflux-ephemeral-1000")

	if err := os.Mkdir(theirs, 0o700); err != nil {
		t.Fatal(err)
	}

	if os.Geteuid() == 0 {
		// Root can make one that belongs to somebody else.
		if err := os.Chown(theirs, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	} else if err := os.Chmod(theirs, 0o757); err != nil {
		// Anybody else can make one every account may write.
		t.Fatal(err)
	}

	next := filepath.Join(t.TempDir(), "conflux-ephemeral")

	d, err := ephemeralIn([]string{theirs, next})
	if err != nil {
		t.Fatal(err)
	}

	if d.State != next {
		t.Errorf("Ephemeral chose %s, want %s past the one another account made", d.State, next)
	}

	if _, err := ephemeralIn([]string{theirs}); err == nil {
		t.Error("with no candidate of its own, Ephemeral chose the one another account made")
	}
}
