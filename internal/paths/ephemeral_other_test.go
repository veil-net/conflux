//go:build !windows

package paths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestEphemeralPassesOverARootAnotherAccountMade: /tmp lets anybody make the name an ephemeral run's
// root would have, and a root secure would refuse is passed over for the next candidate rather than
// taken, or none taken: one Foreign refuses -- another account's, or one another account may write --
// one root owns, for any other account, as secure refuses it, and a link of this account's that leads
// nowhere, which is no root that is not there.
func TestEphemeralPassesOverARootAnotherAccountMade(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	theirs := filepath.Join(t.TempDir(), "conflux-ephemeral-1000")

	if err := os.Mkdir(theirs, 0o700); err != nil {
		t.Fatal(err)
	}

	candidates := map[string]string{"another account's": theirs}

	if os.Geteuid() == 0 {
		// Root can make one that belongs to somebody else.
		if err := os.Chown(theirs, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	} else {
		// Anybody else can make one every account may write, and finds one root owns.
		if err := os.Chmod(theirs, 0o757); err != nil {
			t.Fatal(err)
		}

		candidates["root's"] = "/"
	}

	dangling := filepath.Join(t.TempDir(), "conflux-ephemeral")
	if err := os.Symlink(filepath.Join(t.TempDir(), "nowhere"), dangling); err != nil {
		t.Fatal(err)
	}

	candidates["a link leading nowhere"] = dangling

	for name, c := range candidates {
		next := filepath.Join(t.TempDir(), "conflux-ephemeral")

		d, err := ephemeralIn([]string{c, next})
		if err != nil {
			t.Fatal(err)
		}

		if d.State != next {
			t.Errorf("Ephemeral chose %s, want %s past %s, %s", d.State, next, name, c)
		}

		if _, err := ephemeralIn([]string{c}); err == nil {
			t.Errorf("with no candidate of its own, Ephemeral chose %s, %s", name, c)
		}
	}
}

// TestACandidateNotThereIsReadNoFurther: an ephemeral run's root that is not there is fs.ErrNotExist
// to Foreign, not nil, so a reader takes it for no run and reads nothing at its name, where whoever
// may make a name in its directory -- /tmp lets anybody -- could have made one since. Ephemeral then
// judges where the root would be made by the directory it would be made in, and not by what is at its
// name by then: here a link to itself, which a look at the filesystem holding it would fail on.
func TestACandidateNotThereIsReadNoFurther(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	c := filepath.Join(t.TempDir(), ephemeralName)

	if err := Foreign(c); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Foreign(%s, which is not there) = %v, want %v", c, err, fs.ErrNotExist)
	}

	got, err := FirstExecutable([]string{c}, func(c string) error {
		err := Foreign(c)

		if err := os.Symlink(c, c); err != nil {
			t.Fatal(err)
		}

		return err
	})
	if err != nil || got != c {
		t.Errorf("FirstExecutable, with a link made at %s once Foreign found nothing there, = %q, %v, want it, "+
			"judged by where it would be made", c, got, err)
	}
}
