package cli

import (
	"os"
	"path/filepath"
	"testing"

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

// TestUninstallTakesEveryStaleEphemeralRoot: every root a killed ephemeral run left goes,
// not only the first found, and one a run holds stays.
func TestUninstallTakesEveryStaleEphemeralRoot(t *testing.T) {
	roots := []string{filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")}

	for _, root := range roots {
		if err := paths.EphemeralDirs(root).EnsureAll(); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(paths.EphemeralDirs(root).ServeLockFile(), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if got := staleEphemerals(roots); len(got) != 2 {
		t.Fatalf("%d stale roots found, want both", len(got))
	}

	unlock, err := flock.Acquire(paths.EphemeralDirs(roots[1]).ServeLockFile())
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	if got := staleEphemerals(roots); len(got) != 1 || got[0].Root != roots[0] {
		t.Errorf("stale roots %v, want only %s", got, roots[0])
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
