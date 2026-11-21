//go:build !windows

package paths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEphemeralRemakesARootNotAsConfluxMakesOne: what is at a candidate's name and is not as conflux
// makes a root (Check) is removed as itself and the root made afresh there (EnsureAll), the candidate
// then taken: another account's, or one another account may write; a link that leads nowhere; and one to
// a directory of this account's own, which is left as it was. Only a candidate it cannot remake is passed
// over for the next, or none taken: one in a directory this account may not remove anything from, as
// /tmp lets anybody make the name first and only its owner remove it.
func TestEphemeralRemakesARootNotAsConfluxMakesOne(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	theirs := filepath.Join(t.TempDir(), "conflux-ephemeral-1000")

	if err := os.Mkdir(theirs, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(theirs, "planted"), []byte("theirs"), 0o600); err != nil {
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

	own := t.TempDir()

	for name, target := range map[string]string{
		"a link leading nowhere":                      filepath.Join(t.TempDir(), "nowhere"),
		"a link to a directory of this account's own": own,
	} {
		link := filepath.Join(t.TempDir(), "conflux-ephemeral")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}

		candidates[name] = link
	}

	for name, c := range candidates {
		if err := EphemeralDirs(c).Check(); err == nil || !strings.Contains(err.Error(), "next up --ephemeral") {
			t.Errorf("Check(%s, %s) = %v, want a refusal saying the next ephemeral run makes it afresh", name, c, err)
		}

		next := filepath.Join(t.TempDir(), "conflux-ephemeral")

		d, err := ephemeralIn([]string{c, next})
		if err != nil || d.State != c {
			t.Errorf("Ephemeral past %s, %s, chose %s (%v), want it made afresh", name, c, d.State, err)
		}

		if err := d.Check(); err != nil {
			t.Errorf("Check(%s, which Ephemeral made afresh) = %v", c, err)
		}

		if _, err := os.Lstat(filepath.Join(c, "planted")); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s made afresh holds what was planted (Lstat: %v)", c, err)
		}
	}

	if names, err := os.ReadDir(own); err != nil || len(names) > 0 {
		t.Errorf("where a link at a candidate's name led changed: %v, %v", names, err)
	}

	if os.Geteuid() == 0 {
		return // root may remove anything from any directory
	}

	shut := t.TempDir()
	stuck := filepath.Join(shut, "conflux-ephemeral")

	if err := os.Mkdir(stuck, 0o777); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(stuck, 0o777); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(shut, 0o500); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.Chmod(shut, 0o700) })

	next := filepath.Join(t.TempDir(), "conflux-ephemeral")

	if d, err := ephemeralIn([]string{stuck, next}); err != nil || d.State != next {
		t.Errorf("Ephemeral chose %s (%v), want %s past %s, which it cannot remove", d.State, err, next, stuck)
	}

	if _, err := ephemeralIn([]string{stuck}); err == nil || !strings.Contains(err.Error(), stuck) {
		t.Errorf("with no candidate it can make, Ephemeral = %v, want a refusal naming %s", err, stuck)
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
