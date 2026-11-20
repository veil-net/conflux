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
// is refused, naming the directory, and before anything is made in it -- the root, or a directory
// on the way to it -- where that account could have made a junction for MkdirAll and makeRoot to
// follow. The right to create folders there is not that: C:\ gives it to every user, and their
// folder cannot take the place of one that is not theirs. Windows-only, so it runs in CI's
// platforms job alone.
func TestEnsureAllRefusesARootAnotherAccountCanMove(t *testing.T) {
	for _, c := range []struct {
		name    string
		access  windows.ACCESS_MASK
		refused bool
	}{
		{"Users may rename what is in it", fileDeleteChild, true},
		{"Users may create folders in it", 0x4, false}, // FILE_ADD_SUBDIRECTORY
	} {
		for _, under := range []string{"conflux", filepath.Join("made", "conflux")} {
			t.Run(c.name+", "+under, func(t *testing.T) {
				parent := t.TempDir()
				privtest.GrantUsers(t, parent, c.access, windows.NO_INHERITANCE)

				t.Setenv("CONFLUX_DIR", filepath.Join(parent, under))

				err := Default().EnsureAll()

				switch {
				case c.refused && (err == nil || !strings.Contains(err.Error(), parent)):
					t.Errorf("a root in %s was accepted, or the refusal does not name it: %v", parent, err)
				case !c.refused && err != nil:
					t.Errorf("a root in %s was refused: %v", parent, err)
				}

				first := filepath.Join(parent, strings.Split(under, string(filepath.Separator))[0])
				if _, err := os.Lstat(first); c.refused && !errors.Is(err, os.ErrNotExist) {
					t.Errorf("EnsureAll made %s in a directory it refused (%v)", first, err)
				}
			})
		}
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
	want := remakeCommands(t, root, target)

	was := replacing
	t.Cleanup(func() { replacing = was })

	replacing = func(dir string) {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	err := secure(root)
	if err == nil || !strings.Contains(err.Error(), root+" was made again") {
		t.Fatalf("secure(a junction root made again as it was replaced) = %v, want a refusal naming it", err)
	}

	commands := commandsIn(err)
	if !slices.Equal(commands, want) {
		t.Fatalf("the refusal's commands are %q, want %q", commands, want)
	}

	replacing = was

	if !sameVolumeAsProgramFiles(root) {
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

// TestSecureSaysHowToRemakeAJunctionRootItCannotReplace: once secure has removed a junction root, a
// failure to make its own at the name -- here a parent that no longer lets this account create a
// folder in it -- is refused, naming the root and the commands that make the junction again, as
// something made at the name is: with nothing there, the next run would make a root afresh.
// Windows-only, so it runs in CI's platforms job alone.
func TestSecureSaysHowToRemakeAJunctionRootItCannotReplace(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	target := t.TempDir()
	root := mklinkJ(t, filepath.Join(t.TempDir(), "j"), target)
	want := remakeCommands(t, root, target)

	was := replacing
	t.Cleanup(func() { replacing = was })

	replacing = func(dir string) { mayNotAddFolders(t, filepath.Dir(dir)) }

	err := secure(root)
	if err == nil || !strings.Contains(err.Error(), "make a junction of conflux's own at "+root) {
		t.Fatalf("secure(a junction root it cannot make its own at) = %v, want a refusal naming it", err)
	}

	if commands := commandsIn(err); !slices.Equal(commands, want) {
		t.Errorf("the refusal's commands are %q, want %q", commands, want)
	}
}

// remakeCommands are the commands a refusal to replace the junction root, which led to target, says
// make it again: target named as Windows reads it back, its long names in place of %TEMP%'s short
// ones, and the junction made in %ProgramFiles%; none where %ProgramFiles% is not on root's volume.
func remakeCommands(t *testing.T, root, target string) []string {
	t.Helper()

	if !sameVolumeAsProgramFiles(root) {
		return nil
	}

	h, err := openFile(target, readAccess, false)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)

	shown, err := finalPath(h, volumeNameDOS)
	if err != nil {
		t.Fatal(err)
	}

	stage := `%ProgramFiles%\` + filepath.Base(root) + ".junction"

	return []string{
		`rmdir "` + root + `"`,
		`mklink /J "` + stage + `" "` + strings.TrimPrefix(shown, `\\?\`) + `"`,
		`move "` + stage + `" "` + root + `"`,
	}
}

// sameVolumeAsProgramFiles reports whether dir is on the volume %ProgramFiles% is on, by its drive.
func sameVolumeAsProgramFiles(dir string) bool {
	return strings.EqualFold(filepath.VolumeName(os.Getenv("ProgramFiles")), filepath.VolumeName(dir))
}

// TestRemakingAJunctionRootOnAnotherVolume: the commands a refusal gives to make a junction root again
// make it in %ProgramFiles% and move it into place, which move cannot do from one volume to another,
// so for a root on a volume %ProgramFiles% is not on none are given: the refusal says, naming the
// volume, to choose a folder there that only SYSTEM and the Administrators may write. Windows-only,
// so it runs in CI's platforms job alone.
func TestRemakingAJunctionRootOnAnotherVolume(t *testing.T) {
	other := "Q:"
	if sameVolumeAsProgramFiles(other) {
		other = "R:"
	}

	said := remakeJunction(other+`\conflux`, `D:\conflux`)

	if commands := commandsIn(errors.New(said)); len(commands) != 0 ||
		!strings.Contains(said, "%ProgramFiles% is not on "+other+", so choose such a folder there") {
		t.Errorf("remakeJunction(a root on %s) = %q, want no commands and a folder there to choose", other, said)
	}
}

// commandsIn are the lines of err's message that are commands to type, each indented by four
// spaces.
func commandsIn(err error) []string {
	var commands []string

	for line := range strings.Lines(err.Error()) {
		if command, ok := strings.CutPrefix(strings.TrimRight(line, "\n"), "    "); ok {
			commands = append(commands, command)
		}
	}

	return commands
}

// mayNotAddFolders gives dir to this account alone, with full control of it but the right to add a
// folder to it (FILE_ADD_SUBDIRECTORY, 0x4).
func mayNotAddFolders(t *testing.T, dir string) {
	t.Helper()

	me := currentUser().String()
	setSecurity(t, dir, "O:"+me+"D:P(A;;0x1f01fb;;;"+me+")")
}

// TestSecureHoldsAJunctionRoot: a root that is a junction is held to who may point it elsewhere,
// as a link is on Unix to its owner: %ProgramData% lets any user make one where conflux's root
// is not yet, leading into a directory of SYSTEM's, whose owner would answer for it. One whose
// own DACL lets Users write its attributes, enough to rewrite its target, is refused by secure
// and by checkRoot, every reader's, naming it; one only this account and the system may change is
// accepted by both. A root of the platform's, so no CONFLUX_DIR: no parents are read. Windows-only, so it
// runs in CI's platforms job alone.
func TestSecureHoldsAJunctionRoot(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	open := mklinkJ(t, filepath.Join(t.TempDir(), "j"), t.TempDir())
	grantLink(t, open, windows.FILE_WRITE_ATTRIBUTES)

	if err := checkRoot(open); err == nil || !strings.Contains(err.Error(), open) {
		t.Errorf("checkRoot(a junction Users may point elsewhere) = %v, want a refusal naming it", err)
	}

	if err := secure(open); err == nil || !strings.Contains(err.Error(), open) {
		t.Errorf("secure(a junction Users may point elsewhere) = %v, want a refusal naming it", err)
	}

	held := mklinkJ(t, filepath.Join(t.TempDir(), "j"), t.TempDir())

	if err := checkRoot(held); err != nil {
		t.Errorf("checkRoot(a junction only this account and the system may change) = %v", err)
	}

	if err := secure(held); err != nil {
		t.Errorf("secure(a junction only this account and the system may change) = %v", err)
	}
}

// TestARootOnANetworkVolumeIsRefused: who owns what a network volume holds, and whom its DACLs
// grant, are the accounts of the machine serving it, which this one cannot judge, so a root on
// one is refused by secure and by checkRoot alike, naming it and the network volume, as the device
// its handle is open on says and not as it is spelled: reached by its UNC path, through a drive
// mapped to the share, or through a link leading to that drive. Nothing is made there: secure
// refuses it before it fills it, and a CONFLUX_DIR there that is not made yet is refused by
// EnsureAll before it makes the root or anything above it, naming the directory there that is on
// the network volume. A link naming the share itself, on the way to a CONFLUX_DIR, is refused as a
// link before anything follows it (and further in TestALinkLeadingOffThisMachineOrNowhereIsRefused).
// The share is a folder of this machine's, reached through its own server. Windows-only, so it runs
// in CI's platforms job alone, and skipped where the machine will not share a folder.
func TestARootOnANetworkVolumeIsRefused(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	root := foundRoot(t)
	dir := filepath.Dir(root)

	share := privtest.Share(t, dir)
	unc := filepath.Join(share, "conflux")

	drive := privtest.MapDrive(t, share)

	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(filepath.Join(drive, "conflux"), link); err != nil {
		t.Fatal(err)
	}

	for _, root := range []string{unc, filepath.Join(drive, "conflux"), link} {
		for name, judge := range map[string]func(string) error{"checkRoot": checkRoot, "secure": secure} {
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

		if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), root) ||
			!strings.Contains(err.Error(), " is on a network volume") {
			t.Errorf("EnsureAll(a CONFLUX_DIR of %s) = %v, want a refusal naming it and the network volume", root, err)
		}
	}

	// A link naming the share itself, on the way to a CONFLUX_DIR, is refused as a link before
	// anything is looked up through it (walk), and not as the network volume it leads to.
	toShare := dirSymlink(t, filepath.Join(t.TempDir(), "share"), share)
	made := filepath.Join(toShare, "conflux", "made")
	t.Setenv("CONFLUX_DIR", made)

	if err := Default().EnsureAll(); err == nil ||
		!strings.Contains(err.Error(), "resolve "+made+": "+toShare+" is a link conflux cannot follow") ||
		!strings.Contains(err.Error(), "another machine") {
		t.Errorf("EnsureAll(a CONFLUX_DIR of %s) = %v, want a refusal naming the link %s and another machine", made,
			err, toShare)
	}

	if _, err := os.Lstat(filepath.Join(dir, "made")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("EnsureAll made the way to a CONFLUX_DIR on a network volume it refused (%v)", err)
	}
}

// TestALinkLeadingOffThisMachineOrNowhereIsRefused: a link at a root's name, or on the way to a
// CONFLUX_DIR, that names a share is read for where it leads off the link itself, and refused before
// anything follows it, which would sign this machine in to whoever serves the share: by secure and
// checkRoot for a root of the platform's, as itself (heldRoot), and for a CONFLUX_DIR that is the
// link or inside it by EnsureAll and checkRoot, as a link on the way to it (walk), before
// either looks anything up there. The share is 192.0.2.1's, TEST-NET-1, which nothing answers: a
// lookup that followed the link would fail slowly, saying the network path was not found, not as
// these refusals say. A link leading to nothing is refused by them too, as a link conflux cannot
// follow rather than as a root that is not there, and nothing is made where it leads. Windows-only,
// so it runs in CI's platforms job alone.
func TestALinkLeadingOffThisMachineOrNowhereIsRefused(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	const unc = `\\192.0.2.1\share\conflux`

	away := dirSymlink(t, filepath.Join(t.TempDir(), "conflux"), unc)
	nowhere := filepath.Join(t.TempDir(), "nowhere")
	dangling := dirSymlink(t, filepath.Join(t.TempDir(), "conflux"), nowhere)

	for name, judge := range map[string]func(string) error{"checkRoot": checkRoot, "secure": secure} {
		if err := judge(away); err == nil || !strings.Contains(err.Error(), away+" is a link conflux will not follow") ||
			!strings.Contains(err.Error(), `\??\UNC\192.0.2.1\share\conflux`) {
			t.Errorf("%s(a link to %s) = %v, want a refusal naming it and where it leads", name, unc, err)
		}

		if err := judge(dangling); err == nil || !strings.Contains(err.Error(), dangling+" is a link conflux cannot follow") {
			t.Errorf("%s(a link to nothing) = %v, want a refusal naming it", name, err)
		}
	}

	// For a CONFLUX_DIR, by the walk of its way, which reads the link off itself before anything looks
	// up a name through it: makeRoot's for EnsureAll, and parents' in checkRoot for a reader of a root
	// there.
	refusal := func(dir string) string { return "resolve " + dir + ": " + away + " is a link conflux cannot follow" }

	for _, root := range []string{away, filepath.Join(away, "conflux")} {
		t.Setenv("CONFLUX_DIR", root)

		if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), refusal(root)) ||
			!strings.Contains(err.Error(), "may be on another machine") {
			t.Errorf("EnsureAll(a CONFLUX_DIR of %s) = %v, want %q, saying it may be on another machine", root, err,
				refusal(root))
		}

		for _, dir := range []string{root, filepath.Join(root, "ephemeral")} {
			if err := checkRoot(dir); err == nil || !strings.Contains(err.Error(), refusal(dir)) ||
				!strings.Contains(err.Error(), "may be on another machine") {
				t.Errorf("checkRoot(%s), CONFLUX_DIR %s, = %v, want %q, saying it may be on another machine", dir, root,
					err, refusal(dir))
			}
		}
	}

	for _, root := range []string{dangling, filepath.Join(dangling, "conflux")} {
		t.Setenv("CONFLUX_DIR", root)

		if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), dangling+" is a link conflux cannot follow") {
			t.Errorf("EnsureAll(a CONFLUX_DIR of %s) = %v, want a refusal naming the link to nothing", root, err)
		}
	}

	if _, err := os.Lstat(nowhere); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("EnsureAll made %s, where a link it refused leads (%v)", nowhere, err)
	}
}

// dirSymlink makes a directory symbolic link at link naming target, and is link. The target is not
// looked at: os.Symlink stats it to learn whether it is a directory, which for a share reaches for it.
func dirSymlink(t *testing.T, link, target string) string {
	t.Helper()

	l, err := windows.UTF16PtrFromString(link)
	if err != nil {
		t.Fatal(err)
	}

	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}

	if err := windows.CreateSymbolicLink(l, to, windows.SYMBOLIC_LINK_FLAG_DIRECTORY); err != nil {
		t.Fatalf("make a link at %s to %s: %v", link, target, err)
	}

	return link
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
// through that handle, is not made where the junction leads either. That last is a property of the
// create through the handle, which is not known to fail without OBJ_DONT_REPARSE: it checks what
// fill leaves, and is not a red test of the flag, which createDir keeps as defence in depth.
// Windows-only, so it runs in CI's platforms job alone.
func TestSecureRefusesARootThatBecomesAJunction(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	for _, secured := range []bool{false, true} {
		root := foundRoot(t)

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

	root := foundRoot(t)

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
			root := foundRoot(t)

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

	root := foundRoot(t)
	mayNotAddFolders(t, root)

	if err := secure(root); err == nil || !strings.Contains(err.Error(), "could not add "+runName+" to "+root+
		", whose DACL") {
		t.Errorf("secure(a root this account may not create a folder in) = %v, want a refusal saying it could not "+
			"add %s to it, and why", err, runName)
	}
}

// TestSecureHoldsWhatTheRootHolds: what a root found unrestricted holds is judged, by secure before
// it restricts the root and by Foreign, after the check every reader makes of the root itself -- which
// refuses first a root that passes a grant on, as one whose folder only inherits it does -- by its
// own owner and DACL, read without following it, and
// held to who may write it, move it or point it elsewhere: a junction, which conflux makes none of
// there, whoever may point it elsewhere, though where it leads is nobody else's; a folder Users may
// delete, or write the attributes of, enough to make a junction of it while it is empty, or add
// folders to, or write the extended attributes of; one that only inherits the right to write its
// attributes, which a handle opened before the restriction keeps once the restriction has replaced
// it; one passing Users full control of the files made in it, as conflux.log would be in logs\, by
// a grant to them on it that is inherit-only; a folder named anchor that another account owns,
// though it grants anchord what conflux grants it; and one granting anchord that also lets Users
// add to it. conflux's own layout is let through: anchor\ and run\anchord\ granting anchord's
// service SID what MakeAnchordDir grants it, full control of what is made in them among it,
// run\anchord\sock owned by that SID, which the walk does not go into, and a SYSTEM anchord's
// socket in a run\anchord\ of SYSTEM's and the Administrators', a reparse point a lookup does not
// follow. Windows-only, so it runs in CI's platforms job alone.
func TestSecureHoldsWhatTheRootHolds(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	for _, c := range []struct {
		name string
		make func(t *testing.T, root string) string

		// atRoot: the root itself passes the grant on, so Foreign refuses it for its own DACL, as
		// every reader does (checkRoot), before it looks inside.
		atRoot bool
	}{
		{"a junction Users may point elsewhere", func(t *testing.T, root string) string {
			j := mklinkJ(t, filepath.Join(root, "run"), t.TempDir())
			grantLink(t, j, windows.FILE_WRITE_ATTRIBUTES)

			return j
		}, false},
		{"a junction only this account and the system may change", func(t *testing.T, root string) string {
			return mklinkJ(t, filepath.Join(root, "run"), t.TempDir())
		}, false},
		{"a folder Users may delete", func(t *testing.T, root string) string {
			return grantedFolder(t, filepath.Join(root, "logs"), windows.DELETE)
		}, false},
		{"a folder Users may make a junction of", func(t *testing.T, root string) string {
			return grantedFolder(t, filepath.Join(root, "logs"), windows.FILE_WRITE_ATTRIBUTES)
		}, false},
		{"a folder that only inherits Users' right to write its attributes", func(t *testing.T, root string) string {
			privtest.GrantUsers(t, root, windows.FILE_WRITE_ATTRIBUTES, windows.SUB_CONTAINERS_ONLY_INHERIT)

			dir := filepath.Join(root, "logs")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}

			return dir
		}, true},
		{"a folder that passes Users full control of the files made in it", func(t *testing.T, root string) string {
			dir := filepath.Join(root, "logs")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}

			privtest.GrantUsers(t, dir, fileAllAccess, windows.SUB_OBJECTS_ONLY_INHERIT|windows.INHERIT_ONLY)

			return dir
		}, false},
		{"a folder Users may add folders to", func(t *testing.T, root string) string {
			return grantedFolder(t, filepath.Join(root, "logs"), windows.FILE_APPEND_DATA)
		}, false},
		{"a folder Users may write the extended attributes of", func(t *testing.T, root string) string {
			return grantedFolder(t, filepath.Join(root, "logs"), windows.FILE_WRITE_EA)
		}, false},
		{"a folder named anchor that another account owns", func(t *testing.T, root string) string {
			dir := anchordFolder(t, filepath.Join(root, "anchor"), "")
			ownBy(t, dir, privtest.Users)

			return dir
		}, false},
		{"a folder granting anchord that lets Users add to it", func(t *testing.T, root string) string {
			return anchordFolder(t, filepath.Join(root, "anchor"), "(A;;0x2;;;BU)")
		}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := foundRoot(t)

			held := c.make(t, root)

			names := held
			if c.atRoot {
				names = root + " grants "
			}

			if err := Foreign(root); err == nil || !strings.Contains(err.Error(), names) {
				t.Errorf("Foreign(a root holding %s) = %v, want a refusal naming %s", c.name, err, names)
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
// and left as it was; one that only inherits %ProgramData%'s grant to Users, to add to a folder and
// write its attributes, passes, and is restricted. (A reader refuses both: TestCheckHoldsARootAsAReaderNeeds.) Windows-only, so it runs in CI's
// platforms job alone.
func TestSecureRefusesARootWhoseDACLLetsAnotherMoveWhatIsInIt(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	root := foundRoot(t)

	privtest.GrantUsers(t, root, fileDeleteChild, windows.NO_INHERITANCE)

	if err := secure(root); err == nil || !strings.Contains(err.Error(), root) || !strings.Contains(err.Error(), privtest.Users.String()) {
		t.Errorf("secure(a root whose DACL lets Users delete what is in it) = %v, want a refusal naming it and Users", err)
	}

	if privtest.ReadSecurity(t, root).Protected {
		t.Error("the root refused for its DACL was restricted; that refusal comes before anything is changed")
	}

	if _, err := os.Lstat(filepath.Join(root, runName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the root refused for its DACL was filled; that refusal comes before anything is changed (%v)", err)
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
			root := foundRoot(t)

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
// conflux could repair by its owner, this account's, is refused, naming it, by secure and by
// checkRoot alike. Windows-only, so it runs in CI's platforms job alone.
func TestSecureRefusesARootWithNoDACL(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	root := foundRoot(t)

	setSecurity(t, root, "O:"+currentUser().String()+"D:NO_ACCESS_CONTROL")

	if err := checkRoot(root); err == nil || !strings.Contains(err.Error(), root+" has no DACL") {
		t.Errorf("checkRoot(a root with no DACL) = %v, want a refusal naming it", err)
	}

	if err := secure(root); err == nil || !strings.Contains(err.Error(), root+" has no DACL") {
		t.Errorf("secure(a root with no DACL) = %v, want a refusal naming it", err)
	}
}

// TestAReaderRefusesARootItCannotRead: %ProgramData% lets any account make conflux-ephemeral where
// no run has made it yet, and give it a DACL denying everybody the right to read it, so only a root
// that is not there, or under a directory that is not, is taken by Foreign for none, fs.ErrNotExist,
// unread: one this account may not open is refused by the check every reader makes (checkRoot),
// naming it and the denial -- not its owner, which ownerRefusal would refuse too, had it been read --
// rather than taken for a run's or for none.
// Owned by the Guests, a group this process's token does not hold: an owner is let read a DACL
// whatever the DACL says, and an Administrator's token holds Users. Windows-only, so it runs in CI's
// platforms job alone.
func TestAReaderRefusesARootItCannotRead(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	root := foundRoot(t)

	if err := privtest.WithRestore(t, func() error {
		setSecurity(t, root, "O:BGD:P(D;;RC;;;WD)(A;OICI;FA;;;WD)")

		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := checkRoot(root); !errors.Is(err, windows.ERROR_ACCESS_DENIED) || !strings.Contains(err.Error(), root) {
		t.Errorf("checkRoot(a root whose DACL denies everybody the right to read it) = %v, want %v, naming it", err,
			windows.ERROR_ACCESS_DENIED)
	}

	absent := filepath.Join(t.TempDir(), "absent")

	for _, dir := range []string{absent, filepath.Join(absent, "conflux")} {
		if err := Foreign(dir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("Foreign(%s, which is not there) = %v, want %v", dir, err, os.ErrNotExist)
		}
	}
}

// TestCheckHoldsARootAsAReaderNeeds: Check holds each root that is there to its owner and to who
// else may write it, retarget it or change who may, on itself or on what is made in it, as found
// and changing nothing: a root EnsureAll made passes, and one this account owns that grants Users
// the right to add a file to it is refused, naming it and Users, and left with that grant, by Foreign
// too, which is this check before it looks inside; so is one that only inherits %ProgramData%'s
// grant to Users, which conflux never leaves a root with, though secure restricts it. Where no root
// is there Check is fs.ErrNotExist. Windows-only, so it runs in CI's platforms job alone.
func TestCheckHoldsARootAsAReaderNeeds(t *testing.T) {
	made := filepath.Join(t.TempDir(), "conflux")
	t.Setenv("CONFLUX_DIR", made)

	if err := Default().EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	if err := Default().Check(); err != nil {
		t.Errorf("Check(a root EnsureAll made) = %v", err)
	}

	t.Setenv("CONFLUX_DIR", "")

	open := foundRoot(t)
	privtest.GrantUsers(t, open, windows.FILE_WRITE_DATA, windows.NO_INHERITANCE)

	if err := checkRoot(open); err == nil || !strings.Contains(err.Error(), open) || !strings.Contains(err.Error(), "Users") {
		t.Errorf("checkRoot(a root Users may add a file to) = %v, want a refusal naming it and Users", err)
	}

	if err := Foreign(open); err == nil || !strings.Contains(err.Error(), open+" grants ") {
		t.Errorf("Foreign(a root Users may add a file to) = %v, want checkRoot's refusal", err)
	}

	parent := t.TempDir()
	privtest.ProgramDataGrant(t, parent)

	inherits := filepath.Join(parent, "conflux")
	if err := os.Mkdir(inherits, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := checkRoot(inherits); err == nil || !strings.Contains(err.Error(), inherits) || !strings.Contains(err.Error(), "Users") {
		t.Errorf("checkRoot(a root inheriting %%ProgramData%%'s grant to Users) = %v, want a refusal naming it and Users", err)
	}

	users := wellKnown(windows.WinBuiltinUsersSid)
	if !slices.ContainsFunc(privtest.ReadSecurity(t, open).Grantees(), users.Equals) {
		t.Errorf("Check took Users' grant from %s, which it only judges", open)
	}

	absent := filepath.Join(t.TempDir(), "absent")
	if err := (Dirs{Config: absent, State: absent, Run: filepath.Join(absent, runName)}).Check(); !errors.Is(err,
		os.ErrNotExist) {
		t.Errorf("Check(no root there) = %v, want %v", err, os.ErrNotExist)
	}
}

// TestMakeRootGoesIntoNoNameTakenMeanwhile: the way to a CONFLUX_DIR is walked from the top of its
// volume, each folder judged before a name is looked up in it, and the folders missing are made each
// through a handle on the one before and held open as they are made, so what somebody else makes at a
// name meanwhile -- C:\ lets every user make a folder -- answers for nothing it was not judged for.
// Planted at the name the walk looks up, and at each it makes: a junction is followed and judged where
// the walk meets it, and refused, naming it, where it was made once conflux was making the name, with
// nothing made where it leads; a folder whose DACL lets Users rename what is in it is refused, naming
// it, before anything is made in it, but at the root's own name, which is the root, by secure; and a
// plain one, as a conflux making the same root at once makes, is gone into. Windows-only, so it runs
// in CI's platforms job alone.
func TestMakeRootGoesIntoNoNameTakenMeanwhile(t *testing.T) {
	was := looking
	t.Cleanup(func() { looking = was })

	// fresh is a base to make made\conflux in, with CONFLUX_DIR set to it.
	fresh := func(t *testing.T) (step, root string) {
		step = filepath.Join(t.TempDir(), "made")
		root = filepath.Join(step, "conflux")
		t.Setenv("CONFLUX_DIR", root)

		return step, root
	}

	// Where looking is called on a run with nothing planted, from the walk's lookup of made on: made
	// looked up, made made, conflux made.
	_, root := fresh(t)

	var calls []string

	looking = func(p string) { calls = append(calls, p) }

	if err := Default().EnsureAll(); err != nil {
		t.Fatal(err)
	}

	first := slices.Index(calls, filepath.Dir(root))
	if first < 0 || len(calls) < first+3 || !slices.Equal(calls[first:first+3], []string{filepath.Dir(root),
		filepath.Dir(root), root}) {
		t.Fatalf("looking was called with %q, want made looked up and made, then conflux made", calls)
	}

	phases := []string{"looked up", "made", "made, the root"}

	for i, phase := range phases {
		for _, c := range []struct {
			name  string
			plant func(t *testing.T, at string) (elsewhere string)
			// refused is what the refusal for the plant at made, by its phase, and at conflux holds.
			refused func(step, root string) [][]string
		}{
			{"a junction into a folder Users may rename what is in", func(t *testing.T, at string) string {
				open := filepath.Join(t.TempDir(), "open-to-users")
				if err := os.MkdirAll(filepath.Join(open, "real"), 0o700); err != nil {
					t.Fatal(err)
				}

				privtest.GrantUsers(t, open, fileDeleteChild, windows.NO_INHERITANCE)
				mklinkJ(t, at, filepath.Join(open, "real"))

				return filepath.Join(open, "real")
			}, func(step, root string) [][]string {
				made := func(at string) []string {
					return []string{at + ", a junction or a link, was made while conflux made the way to " + root}
				}

				return [][]string{{root + " is inside ", `open-to-users, which grants `}, made(step), made(root)}
			}},
			{"a folder Users may rename what is in", func(t *testing.T, at string) string {
				grantedFolder(t, at, fileDeleteChild)

				return ""
			}, func(step, root string) [][]string {
				inside := []string{root + " is inside " + step + ", which grants "}

				return [][]string{inside, inside, {root + " grants ", "could take out what conflux puts in it"}}
			}},
			{"a plain folder", func(t *testing.T, at string) string {
				if err := os.Mkdir(at, 0o700); err != nil {
					t.Fatal(err)
				}

				return ""
			}, func(string, string) [][]string { return make([][]string, len(phases)) }},
		} {
			t.Run(c.name+", "+phase, func(t *testing.T) {
				step, root := fresh(t)
				at := []string{step, step, root}[i]

				var elsewhere string

				n := 0
				looking = func(p string) {
					if p == at {
						if n++; n == []int{1, 2, 1}[i] {
							elsewhere = c.plant(t, p)
						}
					}
				}

				err := Default().EnsureAll()

				want := c.refused(step, root)[i]
				for _, w := range want {
					if err == nil || !strings.Contains(err.Error(), w) {
						t.Errorf("EnsureAll, with %s planted at %s as it was %s, = %v, want %q", c.name, at, phase,
							err, want)

						break
					}
				}

				if len(want) == 0 && err != nil {
					t.Errorf("EnsureAll, with %s planted at %s as it was %s, = %v", c.name, at, phase, err)
				}

				if elsewhere != "" {
					if entries, err := os.ReadDir(elsewhere); err != nil || len(entries) != 0 {
						t.Errorf("EnsureAll made %v where the junction planted at %s leads (%v)", entries, at, err)
					}
				}
			})
		}
	}
}
