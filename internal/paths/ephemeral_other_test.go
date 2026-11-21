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
// root would have, and what is at a candidate's name and is not as conflux makes a root (Check) is passed
// over for the next candidate rather than taken, or none taken: another account's, or one another
// account may write, which this account could not remove to make its own; a link of this account's that
// leads nowhere; and one to a directory of this account's own.
func TestEphemeralPassesOverARootAnotherAccountMade(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

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

	candidates := map[string]string{"another account's": theirs}

	for name, target := range map[string]string{
		"a link leading nowhere":                      filepath.Join(t.TempDir(), "nowhere"),
		"a link to a directory of this account's own": t.TempDir(),
	} {
		link := filepath.Join(t.TempDir(), "conflux-ephemeral")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}

		candidates[name] = link
	}

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
// to the readers' check (Check), not nil, so a reader takes it for no run and reads nothing at its name, where whoever
// may make a name in its directory -- /tmp lets anybody -- could have made one since. Ephemeral then
// judges where the root would be made by the directory it would be made in, and not by what is at its
// name by then: here a link to itself, which a look at the filesystem holding it would fail on.
func TestACandidateNotThereIsReadNoFurther(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	c := filepath.Join(t.TempDir(), ephemeralName)

	if err := EphemeralDirs(c).Check(); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Check(%s, which is not there) = %v, want %v", c, err, fs.ErrNotExist)
	}

	got, err := FirstExecutable([]string{c}, func(c string) error {
		err := EphemeralDirs(c).Check()

		if err := os.Symlink(c, c); err != nil {
			t.Fatal(err)
		}

		return err
	})
	if err != nil || got != c {
		t.Errorf("FirstExecutable, with a link made at %s once Check found nothing there, = %q, %v, want it, "+
			"judged by where it would be made", c, got, err)
	}
}
