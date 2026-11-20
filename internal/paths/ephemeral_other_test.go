//go:build !windows

package paths

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEphemeralPassesOverARootAnotherAccountMade: /tmp lets anybody make the name an
// ephemeral run's root would have, and one another account made first is refused and
// cannot be removed by this one, so the next candidate is taken rather than none.
func TestEphemeralPassesOverARootAnotherAccountMade(t *testing.T) {
	theirs := filepath.Join(t.TempDir(), "conflux-ephemeral-1000")

	if os.Geteuid() == 0 {
		// Root can make one that belongs to somebody else.
		if err := os.Mkdir(theirs, 0o700); err != nil {
			t.Fatal(err)
		}

		if err := os.Chown(theirs, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	} else if err := os.Symlink("/", theirs); err != nil {
		// Anybody else can name one that belongs to root.
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
