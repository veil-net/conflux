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
			state := d.StateFile()
			if err := os.WriteFile(state, nil, 0o600); err != nil {
				t.Fatal(err)
			}

			privtest.SetOwner(t, state, guests)

			return state, func() { privtest.SetOwner(t, state, sidAdmins); os.Remove(state) }
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

// TestRemakeOldGoesIntoNoJunctionTheServiceWouldNotFollow: a junction at an installation's root that the
// SYSTEM service would not follow -- one as mklink makes it in windows.md's recipe, which the
// administrator's own processes may repoint unelevated, to C:\Program Files\Git as easily as to the root
// -- leads RemakeOld to remove nothing where it leads, a lock file the administrator owns there
// included, for EnsureAll to replace it with a junction of conflux's own; once the junction is secured
// as conflux secures one, RemakeOld removes that lock file to make it again. Windows-only, so it runs in
// CI's platforms job alone.
func TestRemakeOldGoesIntoNoJunctionTheServiceWouldNotFollow(t *testing.T) {
	target := filepath.Join(t.TempDir(), "conflux")
	t.Setenv("CONFLUX_DIR", target)

	if err := Default().EnsureAll(); err != nil {
		t.Fatal(err)
	}

	restore := privtest.CreatorOwns(t)

	if err := os.WriteFile(Default().LockFile(), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	restore()

	root := mklinkJ(t, filepath.Join(t.TempDir(), "conflux"), target)
	t.Setenv("CONFLUX_DIR", root)
	d := Default()

	if removed, err := d.RemakeOld(); removed != nil || err != nil {
		t.Errorf("RemakeOld through a junction the service would not follow = %q, %v, want nothing removed", removed, err)
	}

	if _, err := os.Lstat(filepath.Join(target, filepath.Base(d.LockFile()))); err != nil {
		t.Errorf("RemakeOld through a junction the service would not follow removed the lock file: %v", err)
	}

	setOwnSecurity(t, root, "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")

	if removed, err := d.RemakeOld(); err != nil || !slices.Equal(removed, []string{d.LockFile()}) {
		t.Errorf("RemakeOld through a junction secured as conflux secures one = %q, %v, want %s removed", removed, err,
			d.LockFile())
	}
}

// TestRemakeOldEmptiesNoSharedFolder: RemakeOld removes what fails the service's rule only from a root
// of conflux's, so a CONFLUX_DIR of a folder other accounts share, as %ProgramData% is -- Users let add
// to it, CREATOR OWNER passed full control -- holding a lock file the administrator owns, which
// RemakeOld would make again in a root of conflux's, is refused, saying why, before anything is
// removed, and the lock file is left. Windows-only, so it runs in CI's platforms job alone.
func TestRemakeOldEmptiesNoSharedFolder(t *testing.T) {
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}

	privtest.SetSecurity(t, shared, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;CI;0x6;;;BU)(A;OICIIO;FA;;;CO)")

	t.Setenv("CONFLUX_DIR", shared)
	d := Default()

	restore := privtest.CreatorOwns(t)

	if err := os.WriteFile(d.LockFile(), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	restore()

	if removed, err := d.RemakeOld(); removed != nil || err == nil || !strings.Contains(err.Error(), "a folder other accounts share") {
		t.Errorf("RemakeOld(a CONFLUX_DIR of a folder other accounts share) = %q, %v, want a refusal saying so, nothing "+
			"removed", removed, err)
	}

	if _, err := os.Lstat(d.LockFile()); err != nil {
		t.Errorf("RemakeOld refusing a shared folder removed %s: %v", d.LockFile(), err)
	}
}

// TestRemakeOldKeepsNoLogOfTwoNames: the log in a logs\ RemakeOld removes is moved into the root and back
// once logs\ is made again only where it is one file of one name: a hard link at conflux.log to a file
// elsewhere carries that file's owner and DACL, which the service's rule takes, and would have the
// service append its log there. So it goes with the folder, the name removed and the file it named left
// as it was. Windows-only, so it runs in CI's platforms job alone.
func TestRemakeOldKeepsNoLogOfTwoNames(t *testing.T) {
	root := filepath.Join(t.TempDir(), "conflux")
	t.Setenv("CONFLUX_DIR", root)
	d := Default()

	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(elsewhere, []byte("not a log"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.RemoveAll(d.Log); err != nil {
		t.Fatal(err)
	}

	restore := privtest.CreatorOwns(t)

	if err := os.Mkdir(d.Log, 0o700); err != nil {
		t.Fatal(err)
	}

	restore()

	if err := os.Link(elsewhere, d.LogFile()); err != nil {
		t.Fatal(err)
	}

	removed, err := d.RemakeOld()
	if err != nil || !slices.Contains(removed, d.Log) {
		t.Fatalf("RemakeOld of a logs\\ the administrator owns = %q, %v, want it removed", removed, err)
	}

	if _, err := os.Lstat(filepath.Join(root, keptLog(filepath.Base(d.LogFile())))); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("RemakeOld kept a log of two names (%v), want it gone with the folder", err)
	}

	if b, err := os.ReadFile(elsewhere); err != nil || string(b) != "not a log" {
		t.Errorf("the file the log's second name named is %q, %v, want it as it was", b, err)
	}
}

// TestRemakeOldRemovesWhatGrantsTheAdministratorsNothing: a lock file RemakeOld makes again, planted by
// another account under a DACL that grants the Administrators nothing, is read for its owner and DACL
// with the backup intent an Administrator's privileges give, judged, and removed, as uninstall removes
// one, rather than failing the command it runs in. Windows-only, so it runs in CI's platforms job alone.
func TestRemakeOldRemovesWhatGrantsTheAdministratorsNothing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "conflux")
	t.Setenv("CONFLUX_DIR", root)
	d := Default()

	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	guests, err := windows.CreateWellKnownSid(windows.WinBuiltinGuestsSid)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(d.LockFile(), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	privtest.SetSecurity(t, d.LockFile(), "D:P(A;;FA;;;SY)")
	privtest.SetOwner(t, d.LockFile(), guests)

	if removed, err := d.RemakeOld(); err != nil || !slices.Equal(removed, []string{d.LockFile()}) {
		t.Errorf("RemakeOld of a root holding a lock file that grants the Administrators nothing = %q, %v, want it "+
			"removed", removed, err)
	}
}
