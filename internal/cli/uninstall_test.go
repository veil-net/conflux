package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/paths"
)

// TestUninstallTakesTheInstalledConflux: what install.sh put in place goes -- the executable,
// and the link it made for sudo -- and a link or a file of the same name that is somebody
// else's stays.
func TestUninstallTakesTheInstalledConflux(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "local", "conflux")
	link := filepath.Join(dir, "bin", "conflux")

	for _, d := range []string{filepath.Dir(exe), filepath.Dir(link)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.WriteFile(exe, []byte("conflux"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(exe, link); err != nil {
		t.Fatal(err)
	}

	if err := removeInstalled(exe, link); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{exe, link} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived uninstall (%v)", p, err)
		}
	}

	// A link to something else is not conflux's.
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, nil, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(other, link); err != nil {
		t.Fatal(err)
	}

	if err := removeInstalled(exe, link); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Lstat(link); err != nil {
		t.Errorf("a link that is not conflux's was removed (%v)", err)
	}
}

// removalService is a registered service that records whether it was removed.
type removalService struct {
	noService
	removed *bool
}

func (r removalService) Remove() error { *r.removed = true; return nil }

// TestUninstallIsRefusedWhileAnEphemeralRunIsLive: uninstall removes the account a live
// ephemeral run's anchord runs as, so the run refuses it, --yes or not, before anything of the
// installation or the run is removed.
func TestUninstallIsRefusedWhileAnEphemeralRunIsLive(t *testing.T) {
	e := startingEphemeral(t)

	// Before uninstall runs at all: past the refusal it removes the machine's accounts and its
	// installed conflux, which are not the test's.
	if _, live := liveEphemeral(); !live {
		t.Fatal("the run is not seen as live, so uninstall would not be refused")
	}

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}}); err != nil {
		t.Fatal(err)
	}

	var removed bool

	withServices(t, removalService{removed: &removed})
	asRoot(t, true)

	_, errOut, code := capture(t, "uninstall", "--yes")
	if code != ExitUsage || !strings.Contains(errOut, "an ephemeral anchor is running from "+e.Root) {
		t.Errorf("uninstall --yes beside a live run exited %d:\n%s", code, errOut)
	}

	if removed {
		t.Error("the boot service was removed")
	}

	for _, p := range []string{d.ConfigFile(), e.ServeLockFile(), e.Socket()} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s did not survive the refused uninstall: %v", p, err)
		}
	}
}

// TestUninstallTakesAStaleEphemeralRoot: the root a killed ephemeral run left is stale, and
// one a run holds is not.
func TestUninstallTakesAStaleEphemeralRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "e")

	if err := paths.EphemeralDirs(root).EnsureAll(); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(paths.EphemeralDirs(root).ServeLockFile(), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if d, stale := staleEphemeral(root); !stale || d.Root != root {
		t.Fatalf("staleEphemeral(%s) = %v, %v: a killed run's root is not taken for stale", root, d, stale)
	}

	unlock, err := flock.Acquire(paths.EphemeralDirs(root).ServeLockFile())
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	if _, stale := staleEphemeral(root); stale {
		t.Error("a root a run holds is taken for stale")
	}
}

// TestUninstallTakesThePathEntry: the machine's PATH loses the directory install.ps1 added,
// however it is spelled, and nothing else.
func TestUninstallTakesThePathEntry(t *testing.T) {
	for _, c := range []struct{ path, want string }{
		{`%SystemRoot%\system32;C:\Program Files\conflux;C:\tools`, `%SystemRoot%\system32;C:\tools`},
		{`C:\tools;C:\Program Files\conflux\`, `C:\tools`},
		{`C:\tools;c:\program files\CONFLUX`, `C:\tools`},
		{`C:\tools`, `C:\tools`},
	} {
		if got := withoutDir(c.path, `C:\Program Files\conflux`); got != c.want {
			t.Errorf("withoutDir(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

// TestUpdatePutsThePathEntry: an update that installs conflux where there was none puts its
// directory on the machine's PATH, as install.ps1 does: at the end, where no entry names it
// already, however spelled; and uninstall takes it out again.
func TestUpdatePutsThePathEntry(t *testing.T) {
	const dir = `C:\Program Files\conflux`

	for _, c := range []struct{ path, want string }{
		{`%SystemRoot%\system32;C:\tools`, `%SystemRoot%\system32;C:\tools;` + dir},
		{`C:\tools;`, `C:\tools;` + dir},
		{``, dir},
		{`C:\tools;c:\program files\CONFLUX\`, `C:\tools;c:\program files\CONFLUX\`},
		{dir + `;C:\tools`, dir + `;C:\tools`},
	} {
		got := withDir(c.path, dir)
		if got != c.want {
			t.Errorf("withDir(%q) = %q, want %q", c.path, got, c.want)
		}

		if back := withoutDir(got, dir); back != withoutDir(c.path, dir) {
			t.Errorf("withoutDir(withDir(%q)) = %q, which is not the PATH without it", c.path, back)
		}
	}
}

// TestUninstallReachesTheMachineOnlyThroughItsSeams: the two steps of uninstall that reach past
// the root -- the accounts conflux made and the installed conflux -- go through variables a
// test replaces, and TestMain replaces them for every test, so no test run on a real machine,
// a CI runner's included, can remove its accounts or its conflux.
func TestUninstallReachesTheMachineOnlyThroughItsSeams(t *testing.T) {
	var accounts, installation bool

	wasA, wasI := uninstallAccounts, uninstallInstallation
	uninstallAccounts = func() error { accounts = true; return nil }
	uninstallInstallation = func() error { installation = true; return nil }

	t.Cleanup(func() { uninstallAccounts, uninstallInstallation = wasA, wasI })

	withServices(t, noService{})
	asRoot(t, true)

	t.Cleanup(paths.UseRoot(t.TempDir()))

	if _, errOut, code := capture(t, "uninstall", "--yes"); code != ExitOK {
		t.Fatalf("uninstall --yes exited %d:\n%s", code, errOut)
	}

	if !accounts || !installation {
		t.Errorf("uninstall went past its seams: accounts %v, installation %v", accounts, installation)
	}
}

// failingRemove is a registered boot service whose removal fails.
type failingRemove struct{ noService }

func (failingRemove) Remove() error { return errors.New("systemctl disable failed") }

// TestAFailedUninstallKeepsConflux: the installed conflux is what finishes an uninstall that
// failed part way, so a step that fails keeps it, and the error says so.
func TestAFailedUninstallKeepsConflux(t *testing.T) {
	var installation bool

	was := uninstallInstallation
	uninstallInstallation = func() error { installation = true; return nil }

	t.Cleanup(func() { uninstallInstallation = was })

	withServices(t, failingRemove{})
	asRoot(t, true)

	t.Cleanup(paths.UseRoot(t.TempDir()))

	_, errOut, code := capture(t, "uninstall", "--yes")
	if code != ExitError || installation {
		t.Errorf("uninstall --yes with a removal that fails exited %d, removing the installed conflux: %v\n%s",
			code, installation, errOut)
	}

	if !strings.Contains(errOut, "systemctl disable failed") || !strings.Contains(errOut, "conflux uninstall") {
		t.Errorf("the failed uninstall does not say what failed and that conflux was kept to finish it:\n%s", errOut)
	}
}
