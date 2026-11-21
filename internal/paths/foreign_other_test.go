//go:build !windows

package paths

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
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

// TestJudgeWaysSaysWhatItRefuses: uninstall's pre-flight tells a way another account may change
// (ErrWayRefused) from one that cannot be walked at all -- a CONFLUX_DIR inside a file, whose way holds
// no directory there -- which is none of its kinds, since nobody else need be able to change anything
// for it; and the shared directory that is a platform's own root, which nobody chooses, is refused
// saying it is to be removed, not pointed elsewhere.
func TestJudgeWaysSaysWhatItRefuses(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", filepath.Join(file, "conflux"))

	switch err := Default().JudgeWays(); {
	case err == nil:
		t.Errorf("JudgeWays(a CONFLUX_DIR inside a file) = nil, want a refusal")
	case errors.Is(err, ErrWayRefused), errors.Is(err, ErrSharedRoot), errors.Is(err, ErrForeignRoot):
		t.Errorf("JudgeWays(a CONFLUX_DIR inside a file) = %v, want a refusal of none of its kinds", err)
	}

	shared := filepath.Join(t.TempDir(), "conflux")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(shared, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", "")

	if err := (Dirs{Config: shared, State: shared}).JudgeWays(); !errors.Is(err, ErrSharedRoot) ||
		!strings.Contains(err.Error(), "remove it") {
		t.Errorf("JudgeWays(a platform root that is a sticky directory) = %v, want a refusal saying to remove it", err)
	}
}

// TestARootConfluxCannotLookUpIsRefused: what is at a root's name where conflux cannot look it up in the
// directory it is in -- here a name longer than a directory may hold -- is not judged, so it is refused,
// as none of the kinds uninstall's pre-flight tells apart, by JudgeWays, and by RemoveRoot and
// RemoveKilledRun, which remove nothing: nothing unjudged is removed.
func TestARootConfluxCannotLookUpIsRefused(t *testing.T) {
	root := filepath.Join(t.TempDir(), strings.Repeat("c", 300))
	t.Setenv("CONFLUX_DIR", root)

	switch err := Default().JudgeWays(); {
	case err == nil:
		t.Errorf("JudgeWays(a CONFLUX_DIR conflux cannot look up) = nil, want a refusal")
	case errors.Is(err, ErrWayRefused), errors.Is(err, ErrSharedRoot), errors.Is(err, ErrForeignRoot):
		t.Errorf("JudgeWays(a CONFLUX_DIR conflux cannot look up) = %v, want a refusal of none of its kinds", err)
	}

	if gone, err := RemoveRoot(root); gone || err == nil {
		t.Errorf("RemoveRoot(a root conflux cannot look up) = %v, %v, want a refusal, nothing removed", gone, err)
	}

	if removed, err := RemoveKilledRun(root, ""); len(removed) > 0 || err == nil {
		t.Errorf("RemoveKilledRun(a root conflux cannot look up) = %q, %v, want a refusal, nothing removed", removed, err)
	}
}

// TestNothingInASecuredRootIsAStray: a working installation's root -- one conflux has secured, this
// account's at 0700, holding the installation's own state -- is conflux's already, so what an editor
// leaves beside a hand-edited conflux.json is no stray there: EnsureAll, which the supervisor runs at
// every start, takes it, uninstall's pre-flight (JudgeWays) passes it and RemoveRoot removes it, and a
// killed ephemeral run's root holding its run directory and a note is emptied (RemoveKilledRun). The same
// root widened to 0755 by hand is no longer one conflux secured, and is refused naming the first stray,
// as a directory conflux would adopt is.
func TestNothingInASecuredRootIsAStray(t *testing.T) {
	root := filepath.Join(t.TempDir(), "conflux")
	t.Setenv("CONFLUX_DIR", root)

	d := Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"conflux.json", "conflux.json.bak", "conflux.json~", ".conflux.json.swp"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := d.EnsureAll(); err != nil {
		t.Errorf("EnsureAll(a secured root holding an editor's backups) = %v, want it taken", err)
	}

	if err := d.JudgeWays(); err != nil {
		t.Errorf("JudgeWays(a secured root holding an editor's backups) = %v", err)
	}

	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := d.EnsureAll(); err == nil || !strings.Contains(err.Error(), "holds .conflux.json.swp") {
		t.Errorf("EnsureAll(that root widened to 0755) = %v, want a refusal naming .conflux.json.swp", err)
	}

	if err := d.JudgeWays(); !errors.Is(err, ErrForeignRoot) || !strings.Contains(err.Error(), "holds .conflux.json.swp") {
		t.Errorf("JudgeWays(that root widened to 0755) = %v, want a refusal of a foreign root naming .conflux.json.swp",
			err)
	}

	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}

	if gone, err := RemoveRoot(root); !gone || err != nil {
		t.Errorf("RemoveRoot(a secured root holding an editor's backups) = %v, %v, want it removed", gone, err)
	}

	e := EphemeralDirs(filepath.Join(t.TempDir(), "conflux-ephemeral"))
	if err := e.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	note := filepath.Join(e.State, "notes.txt")
	if err := os.WriteFile(note, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}

	if removed, err := RemoveKilledRun(e.State, e.ServeLockFile()); err != nil || !slices.Contains(removed, note) {
		t.Errorf("RemoveKilledRun(a killed run's secured root holding a note) = %q, %v, want the note removed", removed,
			err)
	}
}

// TestASecuredDirectoryWithoutStateIsHeldToConfluxsNames: a directory this account owns at 0700 is
// secured as conflux secures a root, but one holding nothing of an installation's -- /root, a home kept
// at 0700, a folder an operator made, here holding .profile and notes.txt and the lock a lock taken in it
// left -- is no working root, so a CONFLUX_DIR at it is refused naming the first stray: by EnsureAll, by
// uninstall's pre-flight (JudgeWays, as a foreign root) and by RemoveRoot, which leaves it as it was.
func TestASecuredDirectoryWithoutStateIsHeldToConfluxsNames(t *testing.T) {
	home := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{".profile", "notes.txt", "serve.lock"} {
		if err := os.WriteFile(filepath.Join(home, name), []byte("mine"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("CONFLUX_DIR", home)

	mode, was := asFound(t, home)

	if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), "holds .profile") {
		t.Errorf("EnsureAll(a CONFLUX_DIR at a 0700 directory holding no state) = %v, want a refusal naming .profile", err)
	}

	if err := Default().JudgeWays(); !errors.Is(err, ErrForeignRoot) || !strings.Contains(err.Error(), "holds .profile") {
		t.Errorf("JudgeWays(a CONFLUX_DIR at a 0700 directory holding no state) = %v, want a refusal of a foreign root "+
			"naming .profile", err)
	}

	if gone, err := RemoveRoot(home); gone || err == nil || !strings.Contains(err.Error(), "holds .profile") {
		t.Errorf("RemoveRoot(a 0700 directory holding no state) = %v, %v, want a refusal naming .profile", gone, err)
	}

	if m, h := asFound(t, home); m != mode || !slices.Equal(h, was) {
		t.Errorf("a CONFLUX_DIR at a 0700 directory holding no state was left %v holding %q, want %v holding %q", m, h,
			mode, was)
	}
}

// TestOnlyTheRootJudgedIsAskedWhetherItIsDirectlyUnderSlash: whether a root is directly under the
// filesystem's root is asked of that root alone -- its name, or the "..", of the directory it is -- and
// nothing else there is read, since a mount there whose server is gone would hang every process that makes
// a root: judged under a stand-in for /, holding home/, mnt/ and srv/, none of them is statted. A link
// directly under it, to a directory elsewhere at 0755, is the system's by its name; that directory, named
// as itself, is not.
func TestOnlyTheRootJudgedIsAskedWhetherItIsDirectlyUnderSlash(t *testing.T) {
	slash := t.TempDir()

	for _, name := range []string{"home", "mnt", "srv"} {
		if err := os.Mkdir(filepath.Join(slash, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	root := filepath.Join(slash, "conflux")
	if err := os.MkdirAll(filepath.Join(root, runName), 0o700); err != nil {
		t.Fatal(err)
	}

	elsewhere := t.TempDir()

	link := filepath.Join(slash, "data")
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatal(err)
	}

	var statted []string

	was := statting
	t.Cleanup(func() { statting = was })

	statting = func(p string) { statted = append(statted, p) }

	ps := systemPlacesOf(slash, "", Dirs{})

	if err := sharedRootIn(ps, root, held(t, root)); err != nil {
		t.Errorf("sharedRootIn(a root conflux made, directly under the filesystem's root) = %v, want it taken", err)
	}

	if err := sharedRootIn(ps, link, held(t, elsewhere)); err == nil ||
		!strings.Contains(err.Error(), "directly under the filesystem's root") {
		t.Errorf("sharedRootIn(a link directly under the filesystem's root) = %v, want a refusal saying so", err)
	}

	if err := sharedRootIn(ps, elsewhere, held(t, elsewhere)); err != nil {
		t.Errorf("sharedRootIn(a directory elsewhere, named as itself) = %v, want it taken", err)
	}

	for _, name := range []string{"home", "mnt", "srv", "data"} {
		if p := filepath.Join(slash, name); slices.Contains(statted, p) {
			t.Errorf("judging a root under the filesystem's root statted %s, which is not that root", p)
		}
	}
}

// TestASocketAtARootsNameIsNoRoot: conflux makes only a directory at a root's name, so a socket there is
// not conflux's, by the type the lookup read of it and not by the error opening it as a directory fails
// with, which on macOS and OpenBSD is no ENOTDIR: uninstall's pre-flight refuses it as a foreign root
// (JudgeWays), and RemoveRoot refuses it, each naming it, and the socket is left as it was.
func TestASocketAtARootsNameIsNoRoot(t *testing.T) {
	// Under a short name of its own rather than t.TempDir's, which spells this test's name out, past what
	// a socket's address holds on macOS.
	base, err := os.MkdirTemp("", "cfx")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { os.RemoveAll(base) })

	sock := filepath.Join(base, "conflux")

	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { l.Close() })

	t.Setenv("CONFLUX_DIR", sock)

	if err := Default().JudgeWays(); !errors.Is(err, ErrForeignRoot) || !strings.Contains(err.Error(), sock+" is not a directory") {
		t.Errorf("JudgeWays(a CONFLUX_DIR of a socket) = %v, want a refusal of a foreign root naming it", err)
	}

	if gone, err := RemoveRoot(sock); gone || err == nil || !strings.Contains(err.Error(), sock+" is not a directory") {
		t.Errorf("RemoveRoot(a socket) = %v, %v, want a refusal naming it", gone, err)
	}

	if fi, err := os.Lstat(sock); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Errorf("the socket at the root's name is %v, %v, want it as it was", fi, err)
	}
}

// BenchmarkStrays is the strays check of a root conflux has not secured -- one widened to 0755 -- holding
// what an installation's state root holds, every name of which is conflux's, so each is looked up in the
// list of conflux's names; and the judgement of whether the service's own root holds its state
// (stateIn), which looks names up in the same list.
func BenchmarkStrays(b *testing.B) {
	root := filepath.Join(b.TempDir(), "conflux")
	b.Setenv("CONFLUX_DIR", root)

	d := Default()
	if err := d.EnsureAll(); err != nil {
		b.Fatal(err)
	}

	for _, p := range []string{d.ConfigFile(), d.StateFile(), d.ManifestFile(), d.PrivilegeFile(), d.LockFile(),
		d.ServeLockFile(), d.DaemonConfigFile(), d.ServiceExecutable(), filepath.Join(d.State, wayName)} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			b.Fatal(err)
		}
	}

	for _, dir := range []string{d.AnchorDir(), d.Libexec()} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			b.Fatal(err)
		}
	}

	if err := os.Chmod(root, 0o755); err != nil {
		b.Fatal(err)
	}

	s, err := opened(unix.AT_FDCWD, root)
	if err != nil {
		b.Fatal(err)
	}
	defer s.close()

	b.ReportAllocs()

	for b.Loop() {
		if err := d.strays(root, "", s); err != nil {
			b.Fatal(err)
		}

		if !stateIn(root, s) {
			b.Fatal("stateIn(a root holding its state) = false")
		}
	}
}
