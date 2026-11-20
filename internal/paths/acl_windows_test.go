package paths

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/veil-net/conflux/internal/privtest"
	"golang.org/x/sys/windows"
)

// TestEnsureAllGivesTheRootToAdministrators: the root is made SYSTEM's and
// Administrators', with a DACL %ProgramData%'s grants to Users cannot flow back into,
// and what is created beneath it afterwards inherits that.
func TestEnsureAllGivesTheRootToAdministrators(t *testing.T) {
	root := filepath.Join(t.TempDir(), "conflux")
	t.Setenv("CONFLUX_DIR", root)

	d := Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	onlyTheSystems(t, root)

	// Idempotent: a second call finds it already done.
	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll again: %v", err)
	}

	f := filepath.Join(d.Run, "token")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if !Trusted(f) {
		t.Error("a file created beneath the root is not trusted")
	}
}

func TestRestrictedFilesAreTrusted(t *testing.T) {
	f := filepath.Join(t.TempDir(), "anchord.exe")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Restrict(f, false); err != nil {
		t.Fatalf("Restrict: %v", err)
	}

	if !Trusted(f) {
		t.Error("a file Restrict has just made Administrators' is not trusted")
	}
}

// TestEnsureAllRefusesARootAnotherAccountCanMove: an account granted the right to delete or
// rename what is in a directory above a CONFLUX_DIR can move the root aside and put one of
// its own in its place, with a conflux in it for the service to run as SYSTEM, so the root
// is refused, naming the directory. The right to create folders there is not that: C:\
// gives it to every user, and their folder cannot take the place of one that is not theirs.
func TestEnsureAllRefusesARootAnotherAccountCanMove(t *testing.T) {
	for _, c := range []struct {
		name    string
		access  windows.ACCESS_MASK
		refused bool
	}{
		{"Users may rename what is in it", fileDeleteChild, true},
		{"Users may create folders in it", 0x4, false}, // FILE_ADD_SUBDIRECTORY
	} {
		t.Run(c.name, func(t *testing.T) {
			parent := t.TempDir()
			privtest.GrantUsers(t, parent, c.access, windows.NO_INHERITANCE)

			t.Setenv("CONFLUX_DIR", filepath.Join(parent, "conflux"))

			err := Default().EnsureAll()

			switch {
			case c.refused && (err == nil || !strings.Contains(err.Error(), parent)):
				t.Errorf("a root in %s was accepted, or the refusal does not name it: %v", parent, err)
			case !c.refused && err != nil:
				t.Errorf("a root in %s was refused: %v", parent, err)
			}
		})
	}
}

// grantLink gives Users access to link, a link or junction, beside what its DACL grants already: its
// own DACL, opened as itself, where privtest.GrantUsers's named calls would follow it and change the
// DACL of where it leads.
func grantLink(t *testing.T, link string, access windows.ACCESS_MASK) {
	t.Helper()

	name, err := windows.UTF16PtrFromString(link)
	if err != nil {
		t.Fatal(err)
	}

	h, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)

	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}

	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
		nil, nil, privtest.WithUsers(t, dacl, access, windows.NO_INHERITANCE), nil); err != nil {
		t.Fatal(err)
	}
}

// TestEnsureAllFollowsAJunction: a junction is a link the lookup follows, which Go does not
// report as one, so a root that is a junction, or that one leads to, is held to the
// directories above where it leads too -- here one Users may rename what is in -- and a
// junction on the way is followed rather than taken for a file. A junction is held as well to
// who may point it elsewhere: here Users, granted the right to write its attributes, which
// is enough to rewrite its target, though where it leads is nobody else's.
func TestEnsureAllFollowsAJunction(t *testing.T) {
	open := filepath.Join(t.TempDir(), "open-to-users")
	if err := os.MkdirAll(filepath.Join(open, "real"), 0o700); err != nil {
		t.Fatal(err)
	}

	privtest.GrantUsers(t, open, fileDeleteChild, windows.NO_INHERITANCE)

	junction := mklinkJ(t, filepath.Join(t.TempDir(), "j"), filepath.Join(open, "real"))

	for _, root := range []string{junction, filepath.Join(junction, "conflux")} {
		t.Setenv("CONFLUX_DIR", root)

		if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), "open-to-users") {
			t.Errorf("a root at %s, through a junction into a directory Users may rename what is in, was accepted, "+
				"or the refusal does not name that directory: %v", root, err)
		}
	}

	retargeted := mklinkJ(t, filepath.Join(t.TempDir(), "j"), t.TempDir())
	grantLink(t, retargeted, windows.FILE_WRITE_ATTRIBUTES)

	root := filepath.Join(retargeted, "conflux")
	t.Setenv("CONFLUX_DIR", root)

	if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), retargeted) {
		t.Errorf("a root at %s, through a junction Users may point elsewhere, was accepted, or the refusal does not "+
			"name the junction: %v", root, err)
	}
}

// mklinkJ makes a junction at link that leads to target, and is link.
func mklinkJ(t *testing.T, link, target string) string {
	t.Helper()

	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v\n%s", err, out)
	}

	return link
}

// TestSecureReplacesAJunctionRoot: a handle opened on a junction root while its DACL let somebody
// write its attributes keeps that right once the DACL is tightened, and heldLink judges the DACL as
// found, so secure replaces a junction root with one of its own, made through its own handle with
// Restrict's ownership and DACL and leading to the directory it judged: the handle opened beforehand
// repoints nothing the root's name leads to, and the junction there is SYSTEM's or the
// Administrators' under a protected DACL. Windows-only, so it runs in CI's platforms job alone.
func TestSecureReplacesAJunctionRoot(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	judged := t.TempDir()
	root := mklinkJ(t, filepath.Join(t.TempDir(), "j"), judged)

	early := openToWrite(t, root)
	defer windows.CloseHandle(early)

	if err := secure(root); err != nil {
		t.Fatalf("secure(a junction root only this account and the system may change) = %v", err)
	}

	_ = leadTo(early, t.TempDir()) // the found junction, which the name no longer leads through

	led, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}

	want, err := os.Stat(judged)
	if err != nil {
		t.Fatal(err)
	}

	if !os.SameFile(led, want) {
		t.Errorf("%s no longer leads to %s once a handle opened on it before secure repointed it", root, judged)
	}

	h, err := openFile(root, readAccess, false)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)

	if link, err := nameSurrogate(h); err != nil || !link {
		t.Errorf("%s is no junction once secure replaced it (%v)", root, err)
	}

	if sd, err := security(h); err != nil || !secured(sd) {
		t.Errorf("the junction secure made at %s is not SYSTEM's or the Administrators' under a protected DACL (%v)",
			root, err)
	}
}

// TestSecureRefusesAJunctionRootMadeAgain: secure removes a junction root before it makes its own
// at the name, and something somebody made there meanwhile is refused, naming the root and the
// commands that make the junction again, to where it led by its drive letter: with nothing at the
// name, the next run would make a root afresh there, and the machine a new identity. Followed in a
// folder that passes on %ProgramData%'s grant to Users, where a junction made at the name by
// mklink /J carries that grant and is refused, they leave a junction the next secure accepts and
// replaces with its own, leading where the one found did. Windows-only, so it runs in CI's
// platforms job alone; the commands make the junction in %ProgramFiles%, so they are followed only
// where that is on the root's volume.
func TestSecureRefusesAJunctionRootMadeAgain(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	target := t.TempDir()
	root := mklinkJ(t, filepath.Join(t.TempDir(), "j"), target)

	// target as Windows reads it back, its long names in place of %TEMP%'s short ones.
	h, err := openFile(target, readAccess, false)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)

	shown, err := finalPath(h, volumeNameDOS)
	if err != nil {
		t.Fatal(err)
	}

	stage := `%ProgramFiles%\j.junction`
	want := []string{
		`rmdir "` + root + `"`,
		`mklink /J "` + stage + `" "` + strings.TrimPrefix(shown, `\\?\`) + `"`,
		`move "` + stage + `" "` + root + `"`,
	}

	was := replacing
	t.Cleanup(func() { replacing = was })

	replacing = func(dir string) {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	err = secure(root)
	if err == nil || !strings.Contains(err.Error(), root+" was made again") {
		t.Fatalf("secure(a junction root made again as it was replaced) = %v, want a refusal naming it", err)
	}

	var commands []string

	for line := range strings.Lines(err.Error()) {
		if command, ok := strings.CutPrefix(strings.TrimRight(line, "\n"), "    "); ok {
			commands = append(commands, command)
		}
	}

	if !slices.Equal(commands, want) {
		t.Fatalf("the refusal's commands are %q, want %q", commands, want)
	}

	replacing = was

	if !strings.EqualFold(filepath.VolumeName(os.Getenv("ProgramFiles")), filepath.VolumeName(root)) {
		t.Skipf("%%ProgramFiles%% is not on the volume %s is on, so the commands cannot move a junction into place", root)
	}

	t.Cleanup(func() { os.Remove(filepath.Join(os.Getenv("ProgramFiles"), "j.junction")) })

	privtest.ProgramDataGrant(t, filepath.Dir(root))

	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}

	mklinkJ(t, root, target)

	if err := secure(root); err == nil || !strings.Contains(err.Error(), root) {
		t.Fatalf("secure(a junction made by mklink /J where Users are passed the right to write its attributes) = "+
			"%v, want a refusal naming it", err)
	}

	for _, command := range commands {
		c := exec.Command("cmd")
		c.SysProcAttr = &syscall.SysProcAttr{CmdLine: "cmd /c " + command}

		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", command, err, out)
		}
	}

	if err := secure(root); err != nil {
		t.Fatalf("secure(a junction made again as the refusal says) = %v", err)
	}

	led, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}

	if was, err := os.Stat(target); err != nil || !os.SameFile(led, was) {
		t.Errorf("%s no longer leads to %s once secure took the junction made again (%v)", root, target, err)
	}

	j, err := openFile(root, readAccess, false)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(j)

	if sd, err := security(j); err != nil || !secured(sd) {
		t.Errorf("secure did not replace the junction made again at %s with its own (%v)", root, err)
	}
}

// TestSecureHoldsAJunctionRoot: a root that is a junction is held to who may point it elsewhere,
// as a link is on Unix to its owner: %ProgramData% lets any user make one where conflux's root
// is not yet, leading into a directory of SYSTEM's, whose owner would answer for it. One whose
// own DACL lets Users write its attributes, enough to rewrite its target, is refused by secure
// and by Foreign, naming it; one only this account and the system may change is accepted by
// both. A root of the platform's, so no CONFLUX_DIR: no parents are read. Windows-only, so it
// runs in CI's platforms job alone.
func TestSecureHoldsAJunctionRoot(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	open := mklinkJ(t, filepath.Join(t.TempDir(), "j"), t.TempDir())
	grantLink(t, open, windows.FILE_WRITE_ATTRIBUTES)

	if err := Foreign(open); err == nil || !strings.Contains(err.Error(), open) {
		t.Errorf("Foreign(a junction Users may point elsewhere) = %v, want a refusal naming it", err)
	}

	if err := secure(open); err == nil || !strings.Contains(err.Error(), open) {
		t.Errorf("secure(a junction Users may point elsewhere) = %v, want a refusal naming it", err)
	}

	held := mklinkJ(t, filepath.Join(t.TempDir(), "j"), t.TempDir())

	if err := Foreign(held); err != nil {
		t.Errorf("Foreign(a junction only this account and the system may change) = %v", err)
	}

	if err := secure(held); err != nil {
		t.Errorf("secure(a junction only this account and the system may change) = %v", err)
	}
}

// TestARootOnANetworkVolumeIsRefused: who owns what a network volume holds, and whom its DACLs
// grant, are the accounts of the machine serving it, which this one cannot judge, so a root on
// one is refused by secure and by Foreign alike, naming it and the network volume, as the device
// its handle is open on says and not as it is spelled: reached by its UNC path, through a drive
// mapped to the share, or through a link leading to it. Nothing is made there: secure refuses it
// before it fills it, and a CONFLUX_DIR there that is not made yet is refused by EnsureAll before
// it makes the root or anything above it. The share is a folder of this machine's, reached through
// its own server. Windows-only, so it runs in CI's platforms job alone, and skipped where the
// machine will not share a folder.
func TestARootOnANetworkVolumeIsRefused(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "conflux"), 0o700); err != nil {
		t.Fatal(err)
	}

	share := privtest.Share(t, dir)
	unc := filepath.Join(share, "conflux")

	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(unc, link); err != nil {
		t.Fatal(err)
	}

	drive := privtest.MapDrive(t, share)

	for _, root := range []string{unc, filepath.Join(drive, "conflux"), link} {
		for name, judge := range map[string]func(string) error{"Foreign": Foreign, "secure": secure} {
			if err := judge(root); err == nil || !strings.Contains(err.Error(), root+" is on a network volume") {
				t.Errorf("%s(%s) = %v, want a refusal naming it and the network volume", name, root, err)
			}
		}
	}

	if _, err := os.Lstat(filepath.Join(dir, "conflux", runName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("secure made %s in a root on a network volume it refused (%v)", runName, err)
	}

	for _, root := range []string{filepath.Join(share, "made", "conflux"), filepath.Join(drive, "made", "conflux")} {
		t.Setenv("CONFLUX_DIR", root)

		if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), root+" is on a network volume") {
			t.Errorf("EnsureAll(a CONFLUX_DIR of %s) = %v, want a refusal naming it and the network volume", root, err)
		}
	}

	if _, err := os.Lstat(filepath.Join(dir, "made")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("EnsureAll made the way to a CONFLUX_DIR on a network volume it refused (%v)", err)
	}
}

// TestARootIsMadeWithItsDACL: %ProgramData% passes Users the right to create in what is made in it,
// enough to turn an empty directory into a junction, so a root is made with its own ownership and
// protected DACL set as it is created, and carries that grant not even for an instant: read as
// makeRoot leaves it, before anything else is done, and again once EnsureAll has made one. The
// parent also passes on a denial of WRITE_DAC to whoever owns what is made in it, so a root made
// and then given its DACL would be refused that, and one made with its descriptor never carries
// the entry. One already there is left as it is, for secure. Windows-only, so it runs in CI's
// platforms job alone.
func TestARootIsMadeWithItsDACL(t *testing.T) {
	parent := t.TempDir()

	privtest.ProgramDataGrant(t, parent)
	privtest.DenyOwnersTheirDACL(t, parent)

	made := filepath.Join(parent, "made")
	if err := makeRoot(made); err != nil {
		t.Fatalf("makeRoot: %v", err)
	}

	onlyTheSystems(t, made)

	if err := makeRoot(made); err != nil {
		t.Errorf("makeRoot of a root already there: %v", err)
	}

	root := filepath.Join(parent, "conflux")
	t.Setenv("CONFLUX_DIR", root)

	if err := Default().EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	onlyTheSystems(t, root)
}

// onlyTheSystems fails t unless dir belongs to SYSTEM, the Administrators or this account, under a
// protected DACL whose every entry is SYSTEM's or the Administrators'.
func onlyTheSystems(t *testing.T, dir string) {
	t.Helper()

	s := privtest.ReadSecurity(t, dir)

	if !trusted(s.Owner) {
		t.Errorf("%s belongs to %v", dir, s.Owner)
	}

	if !s.Protected {
		t.Errorf("the DACL of %s is not protected, so %s's grants flow into it", dir, filepath.Dir(dir))
	}

	for _, e := range s.Entries {
		if !e.SID.Equals(sidSystem) && !e.SID.Equals(sidAdmins) {
			t.Errorf("the DACL of %s grants %s", dir, e.SID)
		}
	}
}

// TestSecureRefusesARootThatBecomesAJunction: a root found unrestricted is one Users may have been
// let write, enough to turn it into a junction while it is empty, and to keep a handle that does
// so once its DACL is replaced, and one secured already may have been restricted while such a
// handle was open. So the root is read again, through the handle it was judged through, once it
// is filled, and refused where it became one meanwhile -- here just before secure fills it, found
// unrestricted and secured already alike -- and the run directory it fills the root with, made
// through that handle, is not made where the junction leads either. Windows-only, so it runs in
// CI's platforms job alone.
func TestSecureRefusesARootThatBecomesAJunction(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	for _, secured := range []bool{false, true} {
		root := filepath.Join(t.TempDir(), "conflux")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}

		if secured {
			if err := Restrict(root, true); err != nil {
				t.Fatal(err)
			}
		}

		elsewhere := t.TempDir()

		was := filling
		t.Cleanup(func() { filling = was })

		filling = func(dir string) { mountPoint(t, dir, elsewhere) }

		if err := secure(root); err == nil || !strings.Contains(err.Error(), root+" became a junction") {
			t.Errorf("secure(a root, secured already %v, that became a junction before it was filled) = %v, "+
				"want a refusal naming it", secured, err)
		}

		if _, err := os.Lstat(filepath.Join(elsewhere, runName)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("secure made %s in %s, where the root it filled leads once it became a junction (secured "+
				"already %v): %v", runName, elsewhere, secured, err)
		}

		filling = was
	}
}

// TestSecureJudgesWhatTheRootGainsBeforeItIsRestricted: until a found root is restricted, Users may
// add a folder to it, which keeps them as its owner through the restriction, so what the root holds
// is judged again once it is restricted: here a folder Users own, added as soon as secure has
// restricted the root, is refused, naming it. The root stays restricted, and the next secure, which
// finds it secured, judges what it holds all the same and refuses the folder again rather than
// taking the root as done. Windows-only, so it runs in CI's platforms job alone.
func TestSecureJudgesWhatTheRootGainsBeforeItIsRestricted(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	root := filepath.Join(t.TempDir(), "conflux")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}

	planted := filepath.Join(root, "logs")

	was := restricted
	t.Cleanup(func() { restricted = was })

	restricted = func(string) {
		if err := os.Mkdir(planted, 0o700); err != nil {
			t.Fatal(err)
		}

		ownBy(t, planted, privtest.Users)
	}

	if err := secure(root); err == nil || !strings.Contains(err.Error(), planted) {
		t.Errorf("secure(a root Users added a folder to before it was restricted) = %v, want a refusal naming it", err)
	}

	restricted = was

	if err := secure(root); err == nil || !strings.Contains(err.Error(), planted) {
		t.Errorf("secure(the restricted root still holding that folder) = %v, want a refusal naming it", err)
	}
}

// mountPoint turns the empty directory dir into a junction leading to target, in place, as an
// account that may write its data or its attributes can.
func mountPoint(t *testing.T, dir, target string) {
	t.Helper()

	h := openToWrite(t, dir)
	defer windows.CloseHandle(h)

	if err := leadTo(h, target); err != nil {
		t.Fatalf("make %s a junction: %v", dir, err)
	}
}

// openToWrite opens dir as itself, to write its data and attributes.
func openToWrite(t *testing.T, dir string) windows.Handle {
	t.Helper()

	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}

	h, err := windows.CreateFile(name, windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}

	return h
}

// leadTo makes the empty directory h holds a junction leading to the directory target, as
// setMountPoint makes one.
func leadTo(h windows.Handle, target string) error { return setMountPoint(h, `\??\`+target, target) }

// TestSecureFillsTheRoot: a handle opened on a root, by an account its DACL then let write its
// attributes, keeps that right once the DACL is replaced -- by secure, for a root found
// unrestricted, or before secure finds it, by an administrator restricting it. So secure makes the
// root hold its run directory, SYSTEM's and the Administrators' as it is made, before it judges
// what the root holds, and the handle opened beforehand can no longer make a junction of it: a
// reparse point cannot be set on a directory that is not empty. That holds for a root found
// unrestricted and one secured already, and where secure refuses either for a folder Users own in
// it, once the folder is gone: the root is filled before what it holds is judged. Windows-only, so
// it runs in CI's platforms job alone.
func TestSecureFillsTheRoot(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	for _, c := range []struct {
		name             string
		secured, planted bool
	}{
		{"found unrestricted", false, false},
		{"found unrestricted, holding a folder Users own", false, true},
		{"secured already", true, false},
		{"secured already, holding a folder Users own", true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "conflux")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}

			early := openToWrite(t, root)
			defer windows.CloseHandle(early)

			planted := filepath.Join(root, "logs")

			if c.planted {
				if err := os.Mkdir(planted, 0o700); err != nil {
					t.Fatal(err)
				}

				ownBy(t, planted, privtest.Users)
			}

			if c.secured {
				if err := Restrict(root, true); err != nil {
					t.Fatal(err)
				}
			}

			switch err := secure(root); {
			case c.planted && (err == nil || !strings.Contains(err.Error(), planted)):
				t.Fatalf("secure(a root %s) = %v, want a refusal naming %s", c.name, err, planted)
			case !c.planted && err != nil:
				t.Fatalf("secure(a root %s) = %v", c.name, err)
			}

			onlyTheSystems(t, filepath.Join(root, runName))

			if c.planted {
				if err := os.Remove(planted); err != nil {
					t.Fatal(err)
				}
			}

			if err := leadTo(early, t.TempDir()); !errors.Is(err, windows.ERROR_DIR_NOT_EMPTY) {
				t.Errorf("a handle opened on the root before secure made it a junction afterwards: %v, want %v",
					err, windows.ERROR_DIR_NOT_EMPTY)
			}
		})
	}
}

// TestSecureSaysWhyItCannotFillARoot: secure makes a found root hold its run directory before it
// judges or restricts it, under its DACL as found, so a root whose DACL does not let this account
// create a folder in it is refused there, naming it and saying why, rather than with a bare access
// denied. Windows-only, so it runs in CI's platforms job alone.
func TestSecureSaysWhyItCannotFillARoot(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	root := filepath.Join(t.TempDir(), "conflux")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}

	// Full control but FILE_ADD_SUBDIRECTORY (0x4), for this account alone.
	me := currentUser().String()
	setSecurity(t, root, "O:"+me+"D:P(A;;0x1f01fb;;;"+me+")")

	if err := secure(root); err == nil || !strings.Contains(err.Error(), "could not add "+runName+" to "+root+
		", whose DACL") {
		t.Errorf("secure(a root this account may not create a folder in) = %v, want a refusal saying it could not "+
			"add %s to it, and why", err, runName)
	}
}

// TestSecureHoldsWhatTheRootHolds: what a root found unrestricted holds is judged, by secure before
// it restricts the root and by Foreign, by its own owner and DACL, read without following it, and
// held to who may write it, move it or point it elsewhere: a junction, which conflux makes none of
// there, whoever may point it elsewhere, though where it leads is nobody else's; a folder Users may
// delete, or write the attributes of, enough to make a junction of it while it is empty, or add
// folders to, or write the extended attributes of; one that only inherits the right to write its
// attributes, which a handle opened before the restriction keeps once the restriction has replaced
// it; a folder named anchor that another account owns, though it grants anchord what conflux
// grants it; and one granting anchord that also lets Users add to it. conflux's own layout is let
// through: anchor\ and run\anchord\ granting anchord's service SID what MakeAnchordDir grants it,
// run\anchord\sock owned by that SID, which the walk does not go into, and a SYSTEM anchord's
// socket in a run\anchord\ of SYSTEM's and the Administrators', a reparse point a lookup does not
// follow. Windows-only, so it runs in CI's platforms job alone.
func TestSecureHoldsWhatTheRootHolds(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	for _, c := range []struct {
		name string
		make func(t *testing.T, root string) string
	}{
		{"a junction Users may point elsewhere", func(t *testing.T, root string) string {
			j := mklinkJ(t, filepath.Join(root, "run"), t.TempDir())
			grantLink(t, j, windows.FILE_WRITE_ATTRIBUTES)

			return j
		}},
		{"a junction only this account and the system may change", func(t *testing.T, root string) string {
			return mklinkJ(t, filepath.Join(root, "run"), t.TempDir())
		}},
		{"a folder Users may delete", func(t *testing.T, root string) string {
			return grantedFolder(t, filepath.Join(root, "logs"), windows.DELETE)
		}},
		{"a folder Users may make a junction of", func(t *testing.T, root string) string {
			return grantedFolder(t, filepath.Join(root, "logs"), windows.FILE_WRITE_ATTRIBUTES)
		}},
		{"a folder that only inherits Users' right to write its attributes", func(t *testing.T, root string) string {
			privtest.GrantUsers(t, root, windows.FILE_WRITE_ATTRIBUTES, windows.SUB_CONTAINERS_ONLY_INHERIT)

			dir := filepath.Join(root, "logs")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}

			return dir
		}},
		{"a folder Users may add folders to", func(t *testing.T, root string) string {
			return grantedFolder(t, filepath.Join(root, "logs"), windows.FILE_APPEND_DATA)
		}},
		{"a folder Users may write the extended attributes of", func(t *testing.T, root string) string {
			return grantedFolder(t, filepath.Join(root, "logs"), windows.FILE_WRITE_EA)
		}},
		{"a folder named anchor that another account owns", func(t *testing.T, root string) string {
			dir := anchordFolder(t, filepath.Join(root, "anchor"), "")
			ownBy(t, dir, privtest.Users)

			return dir
		}},
		{"a folder granting anchord that lets Users add to it", func(t *testing.T, root string) string {
			return anchordFolder(t, filepath.Join(root, "anchor"), "(A;;0x2;;;BU)")
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "conflux")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}

			held := c.make(t, root)

			if err := Foreign(root); err == nil || !strings.Contains(err.Error(), held) {
				t.Errorf("Foreign(a root holding %s) = %v, want a refusal naming it", c.name, err)
			}

			if err := secure(root); err == nil || !strings.Contains(err.Error(), held) {
				t.Errorf("secure(a root holding %s) = %v, want a refusal naming it", c.name, err)
			}
		})
	}

	for _, c := range []struct {
		name string
		make func(t *testing.T, root string)
	}{
		{"a SYSTEM anchord's socket", func(t *testing.T, root string) {
			for _, dir := range []string{filepath.Join(root, runName), filepath.Join(root, runName, "anchord")} {
				if err := MakeRestricted(dir); err != nil {
					t.Fatal(err)
				}
			}

			l, err := net.Listen("unix", filepath.Join(root, runName, "anchord", socketName))
			if err != nil {
				t.Fatal(err)
			}

			t.Cleanup(func() { l.Close() })
		}},
		{"anchord's directories, and what anchord made in them", func(t *testing.T, root string) {
			sid, err := ServiceSID()
			if err != nil {
				t.Fatal(err)
			}

			anchordFolder(t, filepath.Join(root, "anchor"), "")

			if err := os.Mkdir(filepath.Join(root, runName), 0o700); err != nil {
				t.Fatal(err)
			}

			sock := filepath.Join(anchordFolder(t, filepath.Join(root, runName, "anchord"), ""), "sock")
			if err := os.WriteFile(sock, nil, 0o600); err != nil {
				t.Fatal(err)
			}

			ownBy(t, sock, sid)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			// Under a short name of its own rather than t.TempDir's, which spells this test's name out:
			// %TEMP% on CI's runner and that name would put the socket's path past the 107 bytes an
			// AF_UNIX address holds. Removed after what make registers, the listener among it, is closed.
			base, err := os.MkdirTemp("", "cfx")
			if err != nil {
				t.Fatal(err)
			}

			t.Cleanup(func() { os.RemoveAll(base) })

			root := filepath.Join(base, "conflux")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}

			c.make(t, root)

			if err := Foreign(root); err != nil {
				t.Errorf("Foreign(a root holding %s) = %v", c.name, err)
			}

			if err := secure(root); err != nil {
				t.Errorf("secure(a root holding %s) = %v", c.name, err)
			}
		})
	}
}

// grantedFolder is the folder dir, made and granted access for Users.
func grantedFolder(t *testing.T, dir string, access windows.ACCESS_MASK) string {
	t.Helper()

	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	privtest.GrantUsers(t, dir, access, windows.NO_INHERITANCE)

	return dir
}

// anchordFolder is the folder dir, made as MakeAnchordDir makes one for anchord's account, with more
// ACEs after: SYSTEM's, which this process may name only with SeRestorePrivilege enabled.
func anchordFolder(t *testing.T, dir, more string) string {
	t.Helper()

	sid, err := ServiceSID()
	if err != nil {
		t.Fatal(err)
	}

	sd, err := windows.SecurityDescriptorFromString(anchordDirSDDL(sid) + more)
	if err != nil {
		t.Fatal(err)
	}

	if err := privtest.WithRestore(t, func() error { return makeDir(dir, sd) }); err != nil {
		t.Fatal(err)
	}

	return dir
}

// ownBy makes sid the owner of path, as only a process with SeRestorePrivilege enabled may name
// an owner it does not carry: this one, an Administrator's, for the moment it takes.
func ownBy(t *testing.T, path string, sid *windows.SID) {
	t.Helper()

	if err := privtest.WithRestore(t, func() error {
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION,
			sid, nil, nil, nil)
	}); err != nil {
		t.Fatalf("give %s to %s: %v", path, sid, err)
	}
}

// TestSecureRefusesARootWhoseDACLLetsAnotherMoveWhatIsInIt: fill keeps a handle opened under a
// found root's old DACL from making a junction of it only while nobody else may take out what fill
// puts there, so a root whose DACL lets Users delete what is in it is refused, naming the grant,
// and left as it was, and passed over by Foreign too; one that only inherits %ProgramData%'s grant
// to Users, to add to a folder and write its attributes, passes. Windows-only, so it runs in CI's
// platforms job alone.
func TestSecureRefusesARootWhoseDACLLetsAnotherMoveWhatIsInIt(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	root := filepath.Join(t.TempDir(), "conflux")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}

	privtest.GrantUsers(t, root, fileDeleteChild, windows.NO_INHERITANCE)

	if err := Foreign(root); err == nil || !strings.Contains(err.Error(), root) || !strings.Contains(err.Error(), privtest.Users.String()) {
		t.Errorf("Foreign(a root whose DACL lets Users delete what is in it) = %v, want a refusal naming it and Users", err)
	}

	if err := secure(root); err == nil || !strings.Contains(err.Error(), root) || !strings.Contains(err.Error(), privtest.Users.String()) {
		t.Errorf("secure(a root whose DACL lets Users delete what is in it) = %v, want a refusal naming it and Users", err)
	}

	if privtest.ReadSecurity(t, root).Protected {
		t.Error("the refused root was restricted; a refusal must change nothing")
	}

	parent := t.TempDir()
	privtest.ProgramDataGrant(t, parent)

	inherits := filepath.Join(parent, "conflux")
	if err := os.Mkdir(inherits, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := secure(inherits); err != nil {
		t.Errorf("secure(a root inheriting %%ProgramData%%'s grant to Users) = %v", err)
	}
}

// TestSecureHoldsAProtectedRootToItsDACL: a root already the Administrators' under a protected DACL
// is one conflux secured only where that DACL lets nobody else write it, move it or change who may,
// nor passes such a right on to what is made in it, as logs\ is made by its name; otherwise it is
// held to what a root found unrestricted is. One granting Users the right to write its attributes,
// or passing them full control of what is made in it, is repaired, left SYSTEM's and the
// Administrators' alone; one granting them the right to delete what is in it, or with no DACL at
// all, which grants anybody everything, is refused, naming it. Windows-only, so it runs in CI's
// platforms job alone.
func TestSecureHoldsAProtectedRootToItsDACL(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	for _, c := range []struct {
		name, sddl string
		refused    bool
	}{
		{"grants Users the right to write its attributes", "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x100;;;BU)", false},
		{"passes Users full control of what is made in it", "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;FA;;;BU)", false},
		{"grants Users the right to delete what is in it", "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x40;;;BU)", true},
		{"has no DACL", "O:BAD:PNO_ACCESS_CONTROL", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "conflux")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}

			setSecurity(t, root, c.sddl)

			err := secure(root)

			switch {
			case c.refused && (err == nil || !strings.Contains(err.Error(), root)):
				t.Errorf("secure(a protected root that %s) = %v, want a refusal naming it", c.name, err)
			case !c.refused && err != nil:
				t.Errorf("secure(a protected root that %s) = %v", c.name, err)
			case !c.refused:
				onlyTheSystems(t, root)
			}
		})
	}
}

// setSecurity gives path the owner and the protected DACL -- or the NULL one, NO_ACCESS_CONTROL --
// that sddl holds, by name.
func setSecurity(t *testing.T, path, sddl string) {
	t.Helper()

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}

	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}

	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

// TestSecureRefusesARootWithNoDACL: a root with no DACL at all grants anybody everything, so a root
// conflux could repair by its owner, this account's, is refused, naming it, by secure and by Foreign
// alike. Windows-only, so it runs in CI's platforms job alone.
func TestSecureRefusesARootWithNoDACL(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	root := filepath.Join(t.TempDir(), "conflux")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}

	setSecurity(t, root, "O:"+currentUser().String()+"D:NO_ACCESS_CONTROL")

	if err := Foreign(root); err == nil || !strings.Contains(err.Error(), root+" has no DACL") {
		t.Errorf("Foreign(a root with no DACL) = %v, want a refusal naming it", err)
	}

	if err := secure(root); err == nil || !strings.Contains(err.Error(), root+" has no DACL") {
		t.Errorf("secure(a root with no DACL) = %v, want a refusal naming it", err)
	}
}
