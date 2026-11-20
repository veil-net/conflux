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

// TestAnchorDirCarries: the directory a flip gives anchord starts from what the last anchor
// kept in the other, and asked again for the same identity it is left as it is.
func TestAnchorDirCarries(t *testing.T) {
	s := &Supervisor{Dirs: dirs(t)}
	d := s.Dirs

	if err := os.MkdirAll(d.AnchorDir(), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(d.AnchorDir(), "cache"), []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}

	s.lastDir = d.AnchorDir()

	dir, err := s.anchorDir(Privilege{})
	if err != nil || dir != d.RootAnchorDir() {
		t.Fatalf("anchorDir = %q, %v; want %q", dir, err, d.RootAnchorDir())
	}

	if b, err := os.ReadFile(filepath.Join(dir, "cache")); err != nil || string(b) != "kept" {
		t.Errorf("the last anchor's state was not carried to root's directory: %q, %v", b, err)
	}

	s.lastDir = dir

	if again, err := s.anchorDir(Privilege{}); err != nil || again != dir {
		t.Errorf("anchorDir again = %q, %v", again, err)
	}
}

// TestAFallbackIsNotARedecision: a start whose account's directories could not be prepared
// runs anchord as the supervisor, and a start or a rebuild that fails after that is not taken
// for a decision that changed -- the next spawn would decide the account again and fall back
// again -- so a refusal for good still counts toward the exit no restart follows, rather than
// respawning anchord every cycle. A decision that did change still is one.
func TestAFallbackIsNotARedecision(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can give the account its directories, so nothing falls back")
	}

	s, _ := supervised(t, "serve")
	s.Drop = true

	// A host that gives the account, whose directories this process, not root, cannot give it.
	groups := []int(nil)
	old := giveTo
	giveTo = func(_ *Supervisor, p *Privilege) string {
		p.As, p.UID, p.GID, p.Groups = "conflux-test", os.Geteuid()+1, os.Getegid()+1, groups

		return ""
	}

	t.Cleanup(func() { giveTo = old })

	_, c, err := s.spawn(t.Context())
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}

	defer s.shutdown(c)

	if s.priv.Account {
		t.Fatal("anchord was started as an account whose directories could not be prepared")
	}

	if s.redecided() {
		t.Error("a start that fell back to the supervisor reads as a decision that changed")
	}

	groups = []int{4242}

	if !s.redecided() {
		t.Error("a decision that did change is not seen")
	}
}
