//go:build !windows

package daemon

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestCopyTreeTakesOnlyTheAnchorsFiles: what the account left in its directory is copied
// for root only as regular files with one name each. A symlink, a hard link to something it
// could name and not read, and a FIFO -- each a way to have root read, block on, or hand
// over something else -- are left behind, and the files they point at are not touched.
func TestCopyTreeTakesOnlyTheAnchorsFiles(t *testing.T) {
	from, to := t.TempDir(), t.TempDir()

	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("root's"), 0o600); err != nil {
		t.Fatal(err)
	}

	write := func(name, body string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(from, name)), 0o700); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(from, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write("bootstrap.json", "peers")
	write("knowledge/realm.json", "links")

	if err := os.Symlink(secret, filepath.Join(from, "link")); err != nil {
		t.Fatal(err)
	}

	if err := os.Link(secret, filepath.Join(from, "hard")); err != nil {
		t.Fatal(err)
	}

	if err := syscall.Mkfifo(filepath.Join(from, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := copyTree(from, to, Privilege{}); err != nil {
		t.Fatal(err)
	}

	for name, want := range map[string]string{"bootstrap.json": "peers", "knowledge/realm.json": "links"} {
		if b, err := os.ReadFile(filepath.Join(to, name)); err != nil || string(b) != want {
			t.Errorf("%s = %q, %v; want %q", name, b, err, want)
		}
	}

	for _, name := range []string{"link", "hard", "fifo"} {
		if _, err := os.Lstat(filepath.Join(to, name)); !os.IsNotExist(err) {
			t.Errorf("%s was copied (%v)", name, err)
		}
	}
}

// TestAnchorDirIsKeptForTheSameIdentity: the directory an identity was given last time is
// given to it again as it is, with what the anchor kept in it.
func TestAnchorDirIsKeptForTheSameIdentity(t *testing.T) {
	s := &Supervisor{Dirs: dirs(t)}
	d := s.Dirs

	dir, err := s.anchorDir(Privilege{})
	if err != nil || dir != d.RootAnchorDir() {
		t.Fatalf("anchorDir = %q, %v; want %q", dir, err, d.RootAnchorDir())
	}

	if err := os.WriteFile(filepath.Join(dir, "bootstrap.json"), []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}

	s.lastDir = dir

	if again, err := s.anchorDir(Privilege{}); err != nil || again != dir {
		t.Errorf("anchorDir again = %q, %v", again, err)
	}

	if b, err := os.ReadFile(filepath.Join(dir, "bootstrap.json")); err != nil || string(b) != "[]" {
		t.Errorf("what the anchor kept is %q, %v; want it kept", b, err)
	}
}
