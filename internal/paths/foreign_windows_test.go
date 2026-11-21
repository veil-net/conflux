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

// TestAForeignRootIsLeftAsItIs: a root whose top level holds a name conflux never makes there is
// somebody else's, and is refused and left untouched, the stray name in the refusal: a CONFLUX_DIR at a
// folder of homes, alice\ and bob\ in it, by EnsureAll, by uninstall's pre-flight (JudgeWays, as a
// foreign root) and by RemoveRoot, its DACL and what it holds as they were; and a junction at the root's
// name, once a root of conflux's, which secure made its own, repointed at that folder, the same way,
// the junction left too. A fresh empty folder, and a root of conflux's holding what conflux makes, are
// taken. Windows-only, so it runs in CI's platforms job alone.
func TestAForeignRootIsLeftAsItIs(t *testing.T) {
	base := t.TempDir()

	homes := filepath.Join(base, "home")
	for _, home := range []string{"alice", "bob"} {
		if err := os.MkdirAll(filepath.Join(homes, home), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// asFound is the folder's DACL's entries and the names it holds.
	asFound := func() (int, []string) {
		entries, err := os.ReadDir(homes)
		if err != nil {
			t.Fatal(err)
		}

		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}

		return len(privtest.ReadSecurity(t, homes).Entries), names
	}

	ours := filepath.Join(base, "ours")
	t.Setenv("CONFLUX_DIR", ours)

	if err := Default().EnsureAll(); err != nil {
		t.Fatalf("EnsureAll(a CONFLUX_DIR not there) = %v", err)
	}

	if err := os.WriteFile(Default().ManifestFile(), []byte("identity"), 0o600); err != nil {
		t.Fatal(err)
	}

	link := mklinkJ(t, filepath.Join(base, "conflux"), ours)
	t.Setenv("CONFLUX_DIR", link)

	if err := Default().EnsureAll(); err != nil {
		t.Fatalf("EnsureAll(a junction to a root of conflux's) = %v, want it taken", err)
	}

	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}

	mklinkJ(t, link, homes)

	for _, root := range []string{homes, link} {
		t.Run(filepath.Base(root), func(t *testing.T) {
			t.Setenv("CONFLUX_DIR", root)

			grants, held := asFound()

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

			if g, h := asFound(); g != grants || !slices.Equal(h, held) {
				t.Errorf("a CONFLUX_DIR of %s was left %d entries holding %q, want %d holding %q", root, g, h, grants,
					held)
			}

			if _, err := os.Lstat(root); err != nil {
				t.Errorf("a CONFLUX_DIR of %s refused is not there: %v", root, err)
			}
		})
	}

	empty := filepath.Join(base, "empty")
	if err := os.Mkdir(empty, 0o700); err != nil {
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

// TestANonDirectoryIsNoRoot: conflux never makes anything but a folder at a root's name, so a file there
// is not conflux's: EnsureAll refuses it, uninstall's pre-flight refuses it as a foreign root
// (JudgeWays), and RemoveRoot refuses it, each naming it, and the file is left as it was. Windows-only,
// so it runs in CI's platforms job alone.
func TestANonDirectoryIsNoRoot(t *testing.T) {
	file := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(file, []byte("127.0.0.1 localhost"), 0o600); err != nil {
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

	if b, err := os.ReadFile(file); err != nil || string(b) != "127.0.0.1 localhost" {
		t.Errorf("the file at the root's name is %q, %v, want it as it was", b, err)
	}
}

// TestAFolderOfWindowsOwnIsNoRoot: a folder directly under a volume's root that Windows made -- owned by
// TrustedInstaller or SYSTEM, as Program Files and ProgramData are -- is no root, by its final path
// whether it names the volume by its letter or its GUID, and a volume's root is none either; a folder
// there that the Administrators own, as conflux makes one, and one deeper down that SYSTEM owns, are
// not refused for where they are. Uninstall's pre-flight refuses a CONFLUX_DIR of %ProgramFiles% as a
// shared root, reading nothing in it. Windows-only, so it runs in CI's platforms job alone.
func TestAFolderOfWindowsOwnIsNoRoot(t *testing.T) {
	owned := func(sddl string) *windows.SECURITY_DESCRIPTOR {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}

		return sd
	}

	const (
		guid   = `\\?\Volume{0b1c2d3e-0000-0000-0000-100000000000}`
		own    = "a folder of Windows' own"
		volume = "a volume's root"
	)

	trustedInstaller := "O:" + sidTrustedInstaller.String() + "D:"

	for _, c := range []struct {
		final, sddl, why string
	}{
		{`\\?\C:\Program Files`, trustedInstaller, own},
		{`\\?\C:\ProgramData`, "O:SYD:", own},
		{guid + `\Windows`, trustedInstaller, own},
		{`\\?\C:\conflux`, "O:BAD:", ""},
		{`\\?\C:\ProgramData\conflux`, "O:SYD:", ""},
		{`\\?\C:\`, "O:BAD:", volume},
		{guid + `\`, "O:BAD:", volume},
	} {
		if why := placeOnVolume(c.final, owned(c.sddl)); !strings.HasPrefix(why, c.why) || (why == "") != (c.why == "") {
			t.Errorf("placeOnVolume(%s, owned %s) = %q, want %q", c.final, c.sddl, why, c.why)
		}
	}

	t.Setenv("CONFLUX_DIR", os.Getenv("ProgramFiles"))

	if err := Default().JudgeWays(); !errors.Is(err, ErrSharedRoot) || !strings.Contains(err.Error(), own) {
		t.Errorf("JudgeWays(a CONFLUX_DIR of %%ProgramFiles%%) = %v, want a refusal of a shared root saying it is %s", err,
			own)
	}
}
