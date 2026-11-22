//go:build !windows

package paths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mode(t *testing.T, dir string) os.FileMode {
	t.Helper()

	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}

	return fi.Mode().Perm()
}

// realTempDir is t.TempDir as the walk names it, no link on the way to it: a TMPDIR behind a link -- on
// macOS /var/folders, under /private -- is named by where the link leads in what the walk names.
func realTempDir(t *testing.T) string {
	t.Helper()

	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	return dir
}

// TestTheWalkGoesAsTheKernelLooksUp: the way is walked as the kernel looks dir up, a link's target read
// from the directory the link is in, ".." included, an absolute one from the top of the volume, and
// ends at the directory dir leads to.
func TestTheWalkGoesAsTheKernelLooksUp(t *testing.T) {
	base := realTempDir(t) // under /private/var on macOS

	for _, dir := range []string{"a", "b/c", "d"} {
		if err := os.MkdirAll(filepath.Join(base, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// a/l -> ../d/m, and d/m -> <base>/b/c, absolute: the root is b/c, reached through d.
	if err := os.Symlink("../d/m", filepath.Join(base, "a", "l")); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(filepath.Join(base, "b", "c"), filepath.Join(base, "d", "m")); err != nil {
		t.Fatal(err)
	}

	// a/up -> ../d: the walk goes back up to base, and on into d, and through m to b/c.
	if err := os.Symlink("../d", filepath.Join(base, "a", "up")); err != nil {
		t.Fatal(err)
	}

	for _, dir := range []string{filepath.Join(base, "a", "l"), filepath.Join(base, "a", "up", "m")} {
		w, err := walk(dir)
		if err != nil {
			t.Fatal(err)
		}

		if w.missing != nil || w.last().path != filepath.Join(base, "b", "c") {
			t.Errorf("the walk to %s ended at %s, %v, want %s, there", dir, w.last().path, w.missing,
				filepath.Join(base, "b", "c"))
		}

		w.close()
	}
}

// TestJudgeReadsAnACLBesideTheMode: an ACL entry that lets anybody add to a directory is refused,
// as its mode's bits would be, ZFS's trivial ACL for a 1777 /tmp among them, and so is one that
// lets an account delete it, or a UUID's write; root's write is nobody else's. Nowhere is a deny
// entry, or the everyone-deny-delete on a macOS home directory, read as anything.
func TestJudgeReadsAnACLBesideTheMode(t *testing.T) {
	const allow, deny = nfs4Allow, 0x0200

	tmp, err := freebsdACL(freebsdBuf(
		[5]uint32{0x01, 0, 0x1ffff, allow},
		[5]uint32{0x40, 0, nfs4AddFile | nfs4AddSubdirectory, allow}), true)
	if err != nil {
		t.Fatal(err)
	}

	moves, err := freebsdACL(freebsdBuf(
		[5]uint32{0x01, 0, 0x1ffff, allow},
		[5]uint32{0x02, 1002, nfs4Delete, allow}), true)
	if err != nil {
		t.Fatal(err)
	}

	home, err := kauthAttr(kauthAttrBuf(kauthEntry{kauthEveryone, deny, kauthDelete}))
	if err != nil {
		t.Fatal(err)
	}

	euid := os.Geteuid()

	for _, c := range []struct {
		name    string
		mode    os.FileMode
		acl     []writer
		refused string
	}{
		{"a /tmp's trivial NFSv4 ACL", os.ModeDir | 0o755, tmp, "anybody"},
		{"an ACL another account may delete it by", os.ModeDir | 0o755, moves, "uid 1002"},
		{"a home directory's deny", os.ModeDir | 0o750, home, ""},
		{"a UUID's write", os.ModeDir | 0o755, []writer{{who: anAccount, uuid: "5B1E0F1C-2D3E-4F50-6172-8394A5B6C7D8"}},
			"5B1E0F1C-2D3E-4F50-6172-8394A5B6C7D8"},
		{"root's write", os.ModeDir | 0o755, []writer{{who: aUser, id: 0}}, ""},
	} {
		got := judge(c.mode, 0, c.acl, false, euid)

		switch {
		case c.refused != "" && !strings.Contains(got, c.refused):
			t.Errorf("%s: judge = %q, want a refusal naming %s", c.name, got, c.refused)
		case c.refused == "" && got != "":
			t.Errorf("%s: judge = %q, want nothing", c.name, got)
		}
	}
}
