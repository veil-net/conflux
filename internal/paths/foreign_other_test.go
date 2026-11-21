//go:build !windows

package paths

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestAForeignRootIsLeftAsItIs: a root whose top level holds a name conflux never makes there is
// somebody else's, and is refused and left untouched, the stray name in the refusal: a CONFLUX_DIR at a
// folder of homes, alice/ and bob/ in it, by EnsureAll, by uninstall's pre-flight (JudgeWays, as a
// foreign root) and by RemoveRoot, its mode and what it holds as they were; and a link at the root's
// name, once a root of conflux's, repointed at that folder, the same way, the link left too. A fresh
// empty folder, and a root of conflux's holding what conflux makes, are taken.
func TestAForeignRootIsLeftAsItIs(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	homes := filepath.Join(base, "home")
	for _, home := range []string{"alice", "bob"} {
		if err := os.MkdirAll(filepath.Join(homes, home), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.Chmod(homes, 0o755); err != nil {
		t.Fatal(err)
	}

	ours := filepath.Join(base, "ours")
	t.Setenv("CONFLUX_DIR", ours)

	if err := Default().EnsureAll(); err != nil {
		t.Fatalf("EnsureAll(a CONFLUX_DIR not there) = %v", err)
	}

	if err := os.WriteFile(Default().ManifestFile(), []byte("identity"), 0o600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(base, "conflux")
	if err := os.Symlink(ours, link); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", link)

	if err := Default().EnsureAll(); err != nil {
		t.Fatalf("EnsureAll(a link to a root of conflux's) = %v, want it taken", err)
	}

	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(homes, link); err != nil {
		t.Fatal(err)
	}

	for _, root := range []string{homes, link} {
		t.Run(filepath.Base(root), func(t *testing.T) {
			t.Setenv("CONFLUX_DIR", root)

			mode, held := asFound(t, homes)

			if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), "holds alice") {
				t.Errorf("EnsureAll(a CONFLUX_DIR of %s) = %v, want a refusal naming alice", root, err)
			}

			if err := Default().JudgeWays(); !errors.Is(err, ErrForeignRoot) || errors.Is(err, ErrWayRefused) ||
				!strings.Contains(err.Error(), "holds alice") {
				t.Errorf("JudgeWays(a CONFLUX_DIR of %s) = %v, want a refusal of a foreign root naming alice", root, err)
			}

			if gone, err := RemoveRoot(root); gone || err == nil || !strings.Contains(err.Error(), "holds alice") {
				t.Errorf("RemoveRoot(%s) = %v, %v, want a refusal naming alice", root, gone, err)
			}

			if m, h := asFound(t, homes); m != mode || !slices.Equal(h, held) {
				t.Errorf("a CONFLUX_DIR of %s was left %v holding %q, want %v holding %q", root, m, h, mode, held)
			}

			if _, err := os.Lstat(root); err != nil {
				t.Errorf("a CONFLUX_DIR of %s refused is not there: %v", root, err)
			}
		})
	}

	empty := filepath.Join(base, "empty")
	if err := os.Mkdir(empty, 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", empty)

	if err := Default().JudgeWays(); err != nil {
		t.Errorf("JudgeWays(a CONFLUX_DIR of a fresh empty folder) = %v", err)
	}

	if err := Default().EnsureAll(); err != nil {
		t.Errorf("EnsureAll(a CONFLUX_DIR of a fresh empty folder) = %v, want it taken", err)
	}

	t.Setenv("CONFLUX_DIR", ours)

	if err := Default().JudgeWays(); err != nil {
		t.Errorf("JudgeWays(a root of conflux's) = %v", err)
	}

	if gone, err := RemoveRoot(ours); !gone || err != nil {
		t.Errorf("RemoveRoot(a root of conflux's) = %v, %v, want it removed", gone, err)
	}
}

// TestANonDirectoryIsNoRoot: conflux never makes anything but a directory at a root's name, so a file
// there -- a CONFLUX_DIR of /etc/passwd's kind -- is not conflux's: EnsureAll refuses it, uninstall's
// pre-flight refuses it as a foreign root (JudgeWays), and RemoveRoot refuses it, each naming it, and
// the file is left as it was.
func TestANonDirectoryIsNoRoot(t *testing.T) {
	file := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(file, []byte("root:x:0:0"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", file)

	if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), file) {
		t.Errorf("EnsureAll(a CONFLUX_DIR of a file) = %v, want a refusal naming it", err)
	}

	if err := Default().JudgeWays(); !errors.Is(err, ErrForeignRoot) || !strings.Contains(err.Error(), file+" is not a directory") {
		t.Errorf("JudgeWays(a CONFLUX_DIR of a file) = %v, want a refusal of a foreign root naming it", err)
	}

	if gone, err := RemoveRoot(file); gone || err == nil || !strings.Contains(err.Error(), file+" is not a directory") {
		t.Errorf("RemoveRoot(a file) = %v, %v, want a refusal naming it", gone, err)
	}

	if b, err := os.ReadFile(file); err != nil || string(b) != "root:x:0:0" {
		t.Errorf("the file at the root's name is %q, %v, want it as it was", b, err)
	}
}

// TestADirectoryDirectlyUnderTheFilesystemsRootIsTheSystems: every directory directly under / is the
// system's, whatever its name -- /home, /opt, /srv, /usr -- so no root may be one, but one conflux made
// a root: its owner's, at 0700 or 0710, and holding something, as every root conflux made holds its
// run directory. Judged under a stand-in for / -- an empty directory at 0755, an empty one of this
// account's at 0700 (/lost+found's kind), and a root conflux made there, at 0700 and 0710 and widened
// to 0755 -- and under / itself, where uninstall's pre-flight refuses a CONFLUX_DIR of /usr as a
// shared root, reading nothing in it.
func TestADirectoryDirectlyUnderTheFilesystemsRootIsTheSystems(t *testing.T) {
	slash := t.TempDir()

	made := func(name string, mode os.FileMode, holds ...string) string {
		dir := filepath.Join(slash, name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}

		for _, h := range holds {
			if err := os.Mkdir(filepath.Join(dir, h), 0o700); err != nil {
				t.Fatal(err)
			}
		}

		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}

		return dir
	}

	cases := []struct {
		dir string
		ok  bool
	}{
		{made("srv", 0o755), false},
		{made("lost+found", 0o700), false},
		{made("conflux", 0o700, runName), true},
		{made("conflux2", 0o710, runName), true},
		{made("wide", 0o755, runName), false},
	}

	ps := systemPlacesOf(slash, "", Dirs{})

	for _, c := range cases {
		err := sharedRootIn(ps, c.dir, held(t, c.dir))

		switch {
		case c.ok && err != nil:
			t.Errorf("sharedRoot(%s, directly under the filesystem's root) = %v, want it taken", c.dir, err)
		case !c.ok && (err == nil || !strings.Contains(err.Error(), "directly under the filesystem's root")):
			t.Errorf("sharedRoot(%s, directly under the filesystem's root) = %v, want a refusal saying so", c.dir, err)
		}
	}

	t.Setenv("CONFLUX_DIR", "/usr")

	if err := Default().JudgeWays(); !errors.Is(err, ErrSharedRoot) || !strings.Contains(err.Error(), "/usr is ") {
		t.Errorf("JudgeWays(a CONFLUX_DIR of /usr) = %v, want a refusal of a shared root", err)
	}
}
