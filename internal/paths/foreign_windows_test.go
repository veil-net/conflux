package paths

import (
	"errors"
	"os"
	"os/exec"
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

// TestTheFolderTheRunningConfluxIsInIsNoRoot: the folder the running conflux is in, and each one above
// it, is no root -- %ProgramFiles%\conflux, where install.ps1 puts conflux, would otherwise be restricted
// and emptied -- refused by uninstall's pre-flight as a shared root, reading nothing in it; but where
// the running conflux is the copy the boot service runs from that folder and the folder already holds the
// installation's own state, its own root, which EnsureAll takes, whatever its DACL, and restricts. A
// conflux of another name there is refused by EnsureAll, naming why; so is a folder holding the running
// conflux alone at the copy's name, as install.ps1 leaves %ProgramFiles%\conflux, as found, its DACL
// inherited; and the folder above the service's root is refused all the same. Windows-only, so it runs in
// CI's platforms job alone.
func TestTheFolderTheRunningConfluxIsInIsNoRoot(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	for _, dir := range []string{filepath.Dir(exe), filepath.Dir(filepath.Dir(exe))} {
		t.Setenv("CONFLUX_DIR", dir)

		if err := Default().JudgeWays(); !errors.Is(err, ErrSharedRoot) || !strings.Contains(err.Error(), "the running conflux is in") {
			t.Errorf("JudgeWays(a CONFLUX_DIR of %s, where the running conflux is) = %v, want a refusal of a shared root "+
				"saying so", dir, err)
		}
	}

	root := filepath.Join(t.TempDir(), "conflux")
	t.Setenv("CONFLUX_DIR", root)

	d := Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{d.ServiceExecutable(), filepath.Join(root, ".conflux-other.exe")} {
		if err := os.WriteFile(p, []byte("conflux"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	was := runningExe
	t.Cleanup(func() { runningExe = was })

	runningExe = func() exePlace { return exePlaceOf(filepath.Join(root, ".conflux-other.exe")) }

	if err := d.EnsureAll(); err == nil || !strings.Contains(err.Error(), "the folder the running conflux is in") {
		t.Errorf("EnsureAll(the root a conflux of another name runs from) = %v, want a refusal saying so", err)
	}

	runningExe = func() exePlace { return exePlaceOf(d.ServiceExecutable()) }

	privtest.GrantUsers(t, root, windows.FILE_WRITE_DATA, windows.NO_INHERITANCE)

	if err := d.EnsureAll(); err != nil {
		t.Errorf("EnsureAll(the service's own root, run as its copy, its DACL letting Users add to it) = %v, want it "+
			"taken", err)
	}

	onlyTheSystems(t, root)

	installed := filepath.Join(t.TempDir(), "conflux")
	if err := os.Mkdir(installed, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(installed, "conflux.exe"), []byte("conflux"), 0o600); err != nil {
		t.Fatal(err)
	}

	runningExe = func() exePlace { return exePlaceOf(filepath.Join(installed, "conflux.exe")) }

	t.Setenv("CONFLUX_DIR", installed)

	if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), "the folder the running conflux is in") {
		t.Errorf("EnsureAll(a folder holding the running conflux alone, at the copy's name) = %v, want a refusal "+
			"saying so", err)
	}

	if entries, err := os.ReadDir(installed); err != nil || len(entries) != 1 {
		t.Errorf("EnsureAll(a folder holding the running conflux alone) left it holding %v (%v), want it as it was",
			entries, err)
	}

	runningExe = func() exePlace { return exePlaceOf(d.ServiceExecutable()) }

	t.Setenv("CONFLUX_DIR", filepath.Dir(root))

	if err := Default().JudgeWays(); !errors.Is(err, ErrSharedRoot) || !strings.Contains(err.Error(), "above the one") {
		t.Errorf("JudgeWays(a CONFLUX_DIR of the folder above the service's root) = %v, want a refusal saying so", err)
	}
}

// TestAVolumesTopIsNoRoot: a CONFLUX_DIR at the top of a volume -- C:\, \\?\C:\, the volume by its GUID,
// or a drive letter SUBST gives a folder -- is held as the top the walk holds, not looked up there by a
// name it does not have, so uninstall's pre-flight refuses it as a shared root before anything is
// removed, the boot service included: a volume's root as one (sharedRoot), and the SUBST letter, whose
// final path is the folder, as the top of a volume nothing holds to remove it from; EnsureAll refuses
// each, and RemoveRoot too, removing nothing. A folder systemFolders names, C:\Users\Public, is refused
// as one. Windows-only, so it runs in CI's platforms job alone.
func TestAVolumesTopIsNoRoot(t *testing.T) {
	drive := os.Getenv("SystemDrive")
	if drive == "" {
		drive = "C:"
	}

	top, err := windows.UTF16PtrFromString(drive + `\`)
	if err != nil {
		t.Fatal(err)
	}

	guid := make([]uint16, windows.MAX_PATH)
	if err := windows.GetVolumeNameForVolumeMountPoint(top, &guid[0], uint32(len(guid))); err != nil {
		t.Fatal(err)
	}

	folder := t.TempDir()
	letter := substLetter(t, folder)

	public, err := windows.KnownFolderPath(windows.FOLDERID_Public, windows.KF_FLAG_DEFAULT)
	if err != nil {
		t.Fatal(err)
	}

	for root, why := range map[string]string{
		drive + `\`:                 "a volume's root",
		`\\?\` + drive + `\`:        "a volume's root",
		windows.UTF16ToString(guid): "a volume's root",
		letter + `\`:                "the top of its volume",
		public:                      "the folder every account shares",
	} {
		t.Setenv("CONFLUX_DIR", root)

		if err := Default().JudgeWays(); !errors.Is(err, ErrSharedRoot) || !strings.Contains(err.Error(), why) {
			t.Errorf("JudgeWays(a CONFLUX_DIR of %s) = %v, want a refusal of a shared root saying it is %s", root, err, why)
		}

		if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("EnsureAll(a CONFLUX_DIR of %s) = %v, want a refusal saying it is %s", root, err, why)
		}

		if gone, err := RemoveRoot(root); gone || err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("RemoveRoot(%s) = %v, %v, want a refusal saying it is %s", root, gone, err, why)
		}
	}

	if entries, err := os.ReadDir(folder); err != nil || len(entries) != 0 {
		t.Errorf("the folder SUBST gave a letter holds %v (%v), want it as it was", entries, err)
	}
}

// substLetter gives folder a drive letter of its own with SUBST, the last one free, taken away when t
// ends, and is it (Z:).
func substLetter(t *testing.T, folder string) string {
	t.Helper()

	drives, err := windows.GetLogicalDrives()
	if err != nil {
		t.Fatal(err)
	}

	for c := 'Z'; c > 'D'; c-- {
		if drives&(1<<(c-'A')) != 0 {
			continue
		}

		letter := string(c) + ":"

		if out, err := exec.Command("subst", letter, folder).CombinedOutput(); err != nil {
			t.Fatalf("subst %s %s: %v\n%s", letter, folder, err, out)
		}

		t.Cleanup(func() { _ = exec.Command("subst", letter, "/d").Run() })

		return letter
	}

	t.Fatal("no drive letter free for SUBST")

	return ""
}

// TestJudgeWaysSaysWhatItRefuses: uninstall's pre-flight tells a way another account may change
// (ErrWayRefused) from one that cannot be walked at all -- a CONFLUX_DIR inside a file -- which is none
// of its kinds; and a shared folder that is the platform's own root, %ProgramData%\conflux as anybody
// may make it before conflux does, is refused saying it is to be removed, not pointed elsewhere.
// Windows-only, so it runs in CI's platforms job alone.
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

	privtest.SetSecurity(t, shared, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;CI;0x6;;;BU)(A;OICIIO;FA;;;CO)")

	t.Setenv("CONFLUX_DIR", "")

	if err := (Dirs{Config: shared, State: shared}).JudgeWays(); !errors.Is(err, ErrSharedRoot) ||
		!strings.Contains(err.Error(), "remove it") {
		t.Errorf("JudgeWays(a platform root that is a folder other accounts share) = %v, want a refusal saying to "+
			"remove it", err)
	}
}
