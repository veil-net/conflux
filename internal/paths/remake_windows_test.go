package paths

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/veil-net/conflux/internal/privtest"
)

// TestRemakeOldRemovesWhatConfluxMakesAgain: a root an older conflux left on a Windows client holds
// logs\, the lock files, bin\ and the service's copy of conflux as the administrator's own, which the
// SYSTEM service refuses, and which a handle opened while the administrator owned them would keep its
// rights to whoever owned them after. RemakeOld removes each of them, a folder with all it holds -- a
// junction in it as itself, never what it leads to -- and leaves the identity, and the log: the log
// file the service's rule takes is moved out of logs\ into the root first, and the one moved aside
// that it refuses goes with the folder; EnsureAll then makes what is its again, the log moved back
// into logs\, and the service's judgement takes the root. What RemakeOld does not make again
// and finds wrong -- the manifest the administrator owns, a file of the Guests', a binary the
// administrator owns in an extraction that is the Administrators', a junction at logs\'s name -- it
// refuses, naming it, and leaves as it is; and an ephemeral run's root, which no service runs from, it
// leaves alone. Windows-only, so it runs in CI's platforms job alone.
func TestRemakeOldRemovesWhatConfluxMakesAgain(t *testing.T) {
	root := filepath.Join(t.TempDir(), "conflux")
	t.Setenv("CONFLUX_DIR", root)
	d := Default()

	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	identity := d.ManifestFile()
	if err := os.WriteFile(identity, []byte("identity"), 0o600); err != nil {
		t.Fatal(err)
	}

	outside := t.TempDir()

	keep := filepath.Join(outside, "keep")
	if err := os.WriteFile(keep, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	set := filepath.Join(d.Libexec(), "set")

	restore := privtest.CreatorOwns(t)

	if err := os.RemoveAll(d.Log); err != nil {
		t.Fatal(err)
	}

	for _, dir := range []string{d.Log, set} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	for _, f := range []string{d.LogFile(), d.LogFile() + ".1", d.LockFile(), filepath.Join(set, "anchord.exe"),
		d.ServiceExecutable()} {
		if err := os.WriteFile(f, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	mklinkJ(t, filepath.Join(d.Log, "j"), outside)

	restore()

	// The log the service wrote is SYSTEM's, whoever owns the folder it is in; the Administrators' does
	// as well for the service's rule.
	privtest.SetOwner(t, d.LogFile(), sidAdmins)

	if err := JudgeAsTheService(root); err == nil || !strings.Contains(err.Error(), ", which belongs to ") {
		t.Fatalf("the service's judgement of a root holding what the administrator owns = %v, want a refusal", err)
	}

	removed, err := d.RemakeOld()
	if err != nil {
		t.Fatalf("RemakeOld of a root holding what the administrator owns = %v", err)
	}

	old := []string{d.Log, d.LockFile(), d.Libexec(), d.ServiceExecutable()}

	slices.Sort(old)
	slices.Sort(removed)

	if !slices.Equal(removed, old) {
		t.Errorf("RemakeOld removed %q, want %q", removed, old)
	}

	for _, p := range old {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is there once RemakeOld removed it (%v)", p, err)
		}
	}

	kept := filepath.Join(root, keptLog(filepath.Base(d.LogFile())))

	for _, p := range []string{keep, identity, kept} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("RemakeOld removed %s: %v", p, err)
		}
	}

	if _, err := os.Lstat(kept + ".1"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("RemakeOld kept the log moved aside, which the service's rule refuses (%v)", err)
	}

	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll of the root RemakeOld left = %v", err)
	}

	if b, err := os.ReadFile(d.LogFile()); err != nil || string(b) != "old" {
		t.Errorf("the log once EnsureAll made logs\\ again = %q, %v, want the one RemakeOld kept", b, err)
	}

	for _, p := range []string{kept, d.LogFile() + ".1"} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is there once EnsureAll moved the log back (%v)", p, err)
		}
	}

	if err := JudgeAsTheService(root); err != nil {
		t.Errorf("the service's judgement of the root RemakeOld and EnsureAll left = %v", err)
	}

	guests, err := windows.CreateWellKnownSid(windows.WinBuiltinGuestsSid)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		make func(t *testing.T) (planted string, undo func())
	}{
		{"the manifest, the administrator's", func(t *testing.T) (string, func()) {
			privtest.SetOwner(t, identity, currentUser())

			return identity, func() { privtest.SetOwner(t, identity, sidAdmins) }
		}},
		{"a file of the Guests'", func(t *testing.T) (string, func()) {
			notes := filepath.Join(root, "notes")
			if err := os.WriteFile(notes, nil, 0o600); err != nil {
				t.Fatal(err)
			}

			privtest.SetOwner(t, notes, guests)

			return notes, func() { privtest.SetOwner(t, notes, sidAdmins); os.Remove(notes) }
		}},
		{"a binary of the administrator's in an extraction of the Administrators'", func(t *testing.T) (string, func()) {
			binary := filepath.Join(set, "anchord.exe")
			if err := os.MkdirAll(set, 0o700); err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(binary, nil, 0o600); err != nil {
				t.Fatal(err)
			}

			privtest.SetOwner(t, binary, currentUser())

			return binary, func() { os.RemoveAll(d.Libexec()) }
		}},
		{"a junction at logs\\'s name", func(t *testing.T) (string, func()) {
			if err := os.RemoveAll(d.Log); err != nil {
				t.Fatal(err)
			}

			return mklinkJ(t, d.Log, outside), func() { os.Remove(d.Log) }
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			planted, undo := c.make(t)
			defer undo()

			if _, err := d.RemakeOld(); err == nil || !strings.Contains(err.Error(), planted) {
				t.Errorf("RemakeOld of a root holding %s = %v, want a refusal naming it", c.name, err)
			}

			for _, p := range []string{planted, keep} {
				if _, err := os.Lstat(p); err != nil {
					t.Errorf("RemakeOld refusing %s removed %s: %v", c.name, p, err)
				}
			}
		})
	}

	e := EphemeralDirs(filepath.Join(t.TempDir(), "conflux-ephemeral"))
	if err := e.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	restore = privtest.CreatorOwns(t)

	if err := os.WriteFile(e.LockFile(), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	restore()

	if removed, err := e.RemakeOld(); removed != nil || err != nil {
		t.Errorf("RemakeOld of an ephemeral run's root = %q, %v, want nothing removed", removed, err)
	}

	if _, err := os.Lstat(e.LockFile()); err != nil {
		t.Errorf("RemakeOld of an ephemeral run's root removed %s: %v", e.LockFile(), err)
	}
}
