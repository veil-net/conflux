package paths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// inData keeps the installation's root in dir, as the system's data folder (SystemData), for the rest of
// the test.
func inData(t *testing.T, dir string) {
	t.Helper()

	was := SystemData
	SystemData = func() string { return dir }

	t.Cleanup(func() { SystemData = was })
}

// TestTheInstallationIsOneFolderInTheSystemsDataFolder: the installation is one folder, DirName, in the
// system's data folder: the configuration and the state the folder itself, the run directory inside it,
// and a log directory inside it only on a platform that writes the service's output to a file.
func TestTheInstallationIsOneFolderInTheSystemsDataFolder(t *testing.T) {
	want := map[string]string{"linux": "/var/lib", "freebsd": "/var/db", "openbsd": "/var/db",
		"darwin": "/Library/Application Support"}[runtime.GOOS]
	if got := systemData(); runtime.GOOS != "windows" && got != want {
		t.Errorf("systemData() = %q, want %q", got, want)
	}

	data := t.TempDir()
	inData(t, data)

	root := filepath.Join(data, DirName)
	d := Default()

	log := ""
	if runtime.GOOS != "linux" && runtime.GOOS != "openbsd" {
		log = filepath.Join(root, "logs")
	}

	if d.Root != root || d.RunDir() != filepath.Join(root, "run") || d.LogDir() != log {
		t.Errorf("Default() = %+v, want everything in %s, the log in %q", d, root, log)
	}
}

// TestCheckRefusesAFileAtARootsName: a file at a root's name is no root of conflux's: the readers'
// check refuses it, naming it, rather than taking it for one there, and reads nothing.
func TestCheckRefusesAFileAtARootsName(t *testing.T) {
	inData(t, t.TempDir())

	d := Default()
	if err := os.WriteFile(d.Root, []byte("a file"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := d.Check(); err == nil || !strings.Contains(err.Error(), d.Root+" is not as conflux makes") ||
		!strings.Contains(err.Error(), "not a directory") {
		t.Errorf("Check(a file at the root's name) = %v, want a refusal naming it", err)
	}
}

// TestEnsureAllMakesOnlyTheFoldersItKeeps: EnsureAll makes the run and log directories in a root where
// they are not there, and the bin directory, which an extraction makes nothing in but its set; and not
// anchor.root/, which the supervisor makes for an anchord that runs as root, and which it only judges
// where it is there.
func TestEnsureAllMakesOnlyTheFoldersItKeeps(t *testing.T) {
	inData(t, t.TempDir())

	d := Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{d.RunDir(), d.LogDir(), d.Libexec()} {
		if fi, err := os.Lstat(p); p != "" && (err != nil || !fi.IsDir()) {
			t.Errorf("EnsureAll did not make %s: %v, %v", p, fi, err)
		}
	}

	if _, err := os.Lstat(d.RootAnchorDir()); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("EnsureAll made %s, which the supervisor makes (Lstat: %v)", d.RootAnchorDir(), err)
	}
}

// TestClearExceptSaysWhatItRemoved: everything in the directory but the one kept is removed, a folder
// with all it holds, and what was removed is named, for tidy to list; the one kept stays, and a
// directory not there is an error, with nothing named.
func TestClearExceptSaysWhatItRemoved(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "keep")

	for _, p := range []string{keep, filepath.Join(dir, "a"), filepath.Join(dir, "c", "d")} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	want := []string{filepath.Join(dir, "a"), filepath.Join(dir, "c")}

	if removed, err := ClearExcept(dir, keep); err != nil || !slices.Equal(removed, want) {
		t.Errorf("ClearExcept = %q, %v, want %q", removed, err, want)
	}

	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 || entries[0].Name() != "keep" {
		t.Errorf("ClearExcept left %v (%v), want only what it kept", entries, err)
	}

	if removed, err := ClearExcept(filepath.Join(dir, "not-there")); err == nil || removed != nil {
		t.Errorf("ClearExcept(a directory not there) = %q, %v, want an error and nothing named", removed, err)
	}
}

// TestOneTestOfWhatIsInsideWhat: a path is inside a root only below it, a name that merely starts with
// ".." included, and the root is not inside itself (above).
func TestOneTestOfWhatIsInsideWhat(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "conflux")

	for dir, want := range map[string]bool{
		filepath.Join(root, "run"):               true,
		filepath.Join(root, "..x"):               true,
		root:                                     false,
		filepath.Join(base, "other"):             false,
		filepath.Join(base, "conflux-elsewhere"): false,
	} {
		if got := above(root, dir); got != want {
			t.Errorf("above(%s, %s) = %v, want %v", root, dir, got, want)
		}
	}
}

// TestTheRootsConfluxMakesPassTheReadersCheck: a reader holds every root to Check, so the installation's
// root EnsureAll makes passes it, on every platform.
func TestTheRootsConfluxMakesPassTheReadersCheck(t *testing.T) {
	inData(t, t.TempDir())

	d := Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	if err := d.Check(); err != nil {
		t.Errorf("Check(the installation's root, which EnsureAll made) = %v", err)
	}
}
