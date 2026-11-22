package paths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// inRuntime keeps an ephemeral run's root in folder, as the runtime folder, for the rest of the test.
func inRuntime(t *testing.T, folder string) {
	t.Helper()

	was := RuntimeFolder
	RuntimeFolder = func() (string, error) { return folder, nil }

	t.Cleanup(func() { RuntimeFolder = was })
}

// TestTheRuntimeFolderIsTheSystems: an ephemeral run's root is DirName in the runtime folder -- /run as
// root, and for anybody else $XDG_RUNTIME_DIR -- and nowhere else: refused, naming the variable, where
// that is not set or is not an absolute path, rather than kept anywhere that outlives a reboot.
func TestTheRuntimeFolderIsTheSystems(t *testing.T) {
	if os.Geteuid() == 0 {
		if got, err := runtimeFolder(); got != "/run" || err != nil {
			t.Errorf("runtimeFolder() as root = %q, %v, want /run", got, err)
		}

		return
	}

	xdg := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", xdg)

	if got, err := runtimeFolder(); got != xdg || err != nil {
		t.Errorf("runtimeFolder() = %q, %v, want %s", got, err, xdg)
	}

	d, err := EphemeralDirs()
	if want := filepath.Join(xdg, DirName); err != nil || d.Root != want ||
		d.RunDir() != filepath.Join(want, "run") || d.LogDir() != "" || !d.IsEphemeral() {
		t.Errorf("EphemeralDirs() = %+v, %v, want everything in %s and no log directory", d, err, want)
	}

	for _, unset := range []string{"", "relative/run"} {
		t.Setenv("XDG_RUNTIME_DIR", unset)

		if got, err := runtimeFolder(); err == nil || !strings.Contains(err.Error(), "XDG_RUNTIME_DIR") {
			t.Errorf("runtimeFolder() with XDG_RUNTIME_DIR=%q = %q, %v, want a refusal naming it", unset, got, err)
		}
	}
}

// TestEphemeralRemakesARootNotAsConfluxMakesOne: what is at the root's name in the runtime folder and is
// not as conflux makes a root (Check) is removed as itself and the root made afresh there (EnsureAll):
// another account's, or one another account may write; a link that leads nowhere; and one to a directory
// of this account's own, which is left as it was. One it cannot remove refuses the run, naming it: there
// is no other place.
func TestEphemeralRemakesARootNotAsConfluxMakesOne(t *testing.T) {
	plant := map[string]func(t *testing.T, root string){
		"another account's": func(t *testing.T, root string) {
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(filepath.Join(root, "planted"), []byte("theirs"), 0o600); err != nil {
				t.Fatal(err)
			}

			if os.Geteuid() == 0 {
				// Root can make one that belongs to somebody else.
				if err := os.Chown(root, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Chmod(root, 0o757); err != nil {
				// Anybody else can make one every account may write.
				t.Fatal(err)
			}
		},
		"a link leading nowhere": func(t *testing.T, root string) {
			if err := os.Symlink(filepath.Join(t.TempDir(), "nowhere"), root); err != nil {
				t.Fatal(err)
			}
		},
	}

	own := t.TempDir()
	plant["a link to a directory of this account's own"] = func(t *testing.T, root string) {
		if err := os.Symlink(own, root); err != nil {
			t.Fatal(err)
		}
	}

	for name, put := range plant {
		t.Run(name, func(t *testing.T) {
			folder := t.TempDir()
			inRuntime(t, folder)

			root := filepath.Join(folder, DirName)
			put(t, root)

			e, err := EphemeralDirs()
			if err != nil {
				t.Fatal(err)
			}

			if err := e.Check(); err == nil || !strings.Contains(err.Error(), "next up --ephemeral") {
				t.Errorf("Check(%s) = %v, want a refusal saying the next ephemeral run makes it afresh", root, err)
			}

			d, err := Ephemeral()
			if err != nil || d.Root != root {
				t.Fatalf("Ephemeral() past %s = %s, %v, want it made afresh", name, d.Root, err)
			}

			if err := d.Check(); err != nil {
				t.Errorf("Check(%s, which Ephemeral made afresh) = %v", root, err)
			}

			if _, err := os.Lstat(filepath.Join(root, "planted")); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("%s made afresh holds what was planted (Lstat: %v)", root, err)
			}
		})
	}

	if names, err := os.ReadDir(own); err != nil || len(names) > 0 {
		t.Errorf("where a link at the root's name led changed: %v, %v", names, err)
	}

	if os.Geteuid() == 0 {
		return // root may remove anything from any directory
	}

	shut := t.TempDir()
	inRuntime(t, shut)

	stuck := filepath.Join(shut, DirName)
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

	if _, err := Ephemeral(); err == nil || !strings.Contains(err.Error(), stuck) {
		t.Errorf("Ephemeral() with %s, which it cannot remove, = %v, want a refusal naming it", stuck, err)
	}
}

// TestARuntimeFolderNotThereOrNoexecIsRefused: a runtime folder that is not there, or is on a filesystem
// mounted noexec, where the extracted anchord could not run, refuses the run, saying which, with nothing
// made or touched: no folder made on the way, and what is at the root's name left as it was. There is no
// other place to keep it.
func TestARuntimeFolderNotThereOrNoexecIsRefused(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "run", "user", "1000")
	inRuntime(t, missing)

	if _, err := Ephemeral(); err == nil || !strings.Contains(err.Error(), "is not there") {
		t.Errorf("Ephemeral() in a runtime folder not there = %v, want a refusal saying so", err)
	}

	if _, err := os.Lstat(filepath.Dir(missing)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Ephemeral() in a runtime folder not there made the way to it (Lstat: %v)", err)
	}

	noexec := t.TempDir()
	inRuntime(t, noexec)

	defer func(was func(string) (bool, error)) { allowsExec = was }(allowsExec)
	allowsExec = func(p string) (bool, error) { return p != noexec, nil }

	root := filepath.Join(noexec, DirName)
	if err := os.Mkdir(root, 0o757); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(root, 0o757); err != nil {
		t.Fatal(err)
	}

	if _, err := Ephemeral(); err == nil || !strings.Contains(err.Error(), "noexec") {
		t.Errorf("Ephemeral() in a noexec runtime folder = %v, want a refusal saying so", err)
	}

	if fi, err := os.Lstat(root); err != nil || fi.Mode().Perm() != 0o757 {
		t.Errorf("Ephemeral() in a noexec runtime folder changed %s: %v, %v", root, fi, err)
	}
}

// TestTheEphemeralRootConfluxMakesPassesTheReadersCheck: a reader holds an ephemeral run's root to Check,
// so the root Ephemeral makes passes it.
func TestTheEphemeralRootConfluxMakesPassesTheReadersCheck(t *testing.T) {
	inRuntime(t, t.TempDir())

	d, err := Ephemeral()
	if err != nil {
		t.Fatal(err)
	}

	if err := d.Check(); err != nil {
		t.Errorf("Check(the ephemeral root Ephemeral made) = %v", err)
	}
}
