package paths

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows a mode is nothing: Go maps Chmod onto the read-only attribute, and
// %ProgramData% lets Users read everything below it and create files and folders in
// it. So conflux replaces the ownership and the DACL instead, and checks them where
// it trusts what it finds.

var (
	sidSystem = wellKnown(windows.WinLocalSystemSid)
	sidAdmins = wellKnown(windows.WinBuiltinAdministratorsSid)
)

func wellKnown(t windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	sid, err := windows.CreateWellKnownSid(t)
	if err != nil {
		panic("paths: " + err.Error())
	}

	return sid
}

// Restrict makes path belong to SYSTEM and Administrators alone: Administrators own
// it, and a protected DACL grants the two of them full control and nobody else
// anything. A directory's grant is inherited by what it holds.
//
// The owner is set rather than left to the creating token, so that everything conflux
// writes passes Trusted whatever the machine's default-owner policy says. A token that
// cannot name Administrators as an owner -- one that is not elevated, which conflux
// never is outside a test -- keeps its own ownership and still gets the DACL. Protected
// is the half that matters for the DACL: without it the parent's ACEs are merged back
// in and the restriction is cosmetic.
func Restrict(path string, dir bool) error {
	inherit := uint32(windows.NO_INHERITANCE)
	if dir {
		inherit = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}

	grant := func(sid *windows.SID, kind windows.TRUSTEE_TYPE) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inherit,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  kind,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}

	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		grant(sidSystem, windows.TRUSTEE_IS_USER),
		grant(sidAdmins, windows.TRUSTEE_IS_GROUP),
	}, nil)
	if err != nil {
		return err
	}

	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)

	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info|windows.OWNER_SECURITY_INFORMATION, sidAdmins, nil, acl, nil)
	if errors.Is(err, windows.ERROR_INVALID_OWNER) {
		err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, acl, nil)
	}

	return err
}

// RestrictToOwner makes path the current account's alone, as a 0600 file or a 0700
// directory is on Unix: a protected DACL granting full control to the account running
// conflux, and to SYSTEM and Administrators, who can take any file anyway. It is for what
// conflux writes for whoever runs it rather than for the machine -- a private key `conflux
// cert` writes, by anybody -- where Restrict, SYSTEM and Administrators alone, would lock an
// ordinary user out of their own file. The owner is left as the creating token made it.
func RestrictToOwner(path string, dir bool) error {
	user := currentUser()
	if user == nil {
		return errors.New("the account this process runs as could not be read from its token")
	}

	inherit := uint32(windows.NO_INHERITANCE)
	if dir {
		inherit = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}

	var entries []windows.EXPLICIT_ACCESS

	for _, t := range []struct {
		sid  *windows.SID
		kind windows.TRUSTEE_TYPE
	}{{user, windows.TRUSTEE_IS_USER}, {sidSystem, windows.TRUSTEE_IS_USER}, {sidAdmins, windows.TRUSTEE_IS_GROUP}} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inherit,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  t.kind,
				TrusteeValue: windows.TrusteeValueFromSID(t.sid),
			},
		})
	}

	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}

	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// Trusted reports whether path is owned by SYSTEM, Administrators or the account
// running conflux -- by somebody who could have written it anyway. Restrict makes
// Administrators the owner of everything conflux writes, so another owner is another
// account's file, and whoever owns a file can grant themselves the right to change it:
// a binary about to run as SYSTEM, found with such an owner, is not run.
func Trusted(path string) bool {
	owner, _, err := ownership(path)

	return err == nil && trusted(owner)
}

// trusted is SYSTEM, Administrators or the account running conflux: somebody who could have
// written anything conflux did.
func trusted(sid *windows.SID) bool {
	return sid.Equals(sidSystem) || sid.Equals(sidAdmins) || isCurrentUser(sid)
}

func ownership(path string) (*windows.SID, windows.SECURITY_DESCRIPTOR_CONTROL, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, 0, err
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return nil, 0, err
	}

	control, _, err := sd.Control()

	return owner, control, err
}

// secure gives a conflux root its ownership and DACL, once, and refuses one another
// account made, or a CONFLUX_DIR another account can move (see parents).
//
// A directory conflux did not create is one somebody else may have filled before it
// looked -- with a binary for the service to run, or a manifest whose key they hold --
// and taking it over would adopt whatever is inside. The account running conflux is
// accepted as well as SYSTEM and Administrators: an administrator's own directory,
// under a policy that makes the creator its owner, is repaired rather than refused.
//
// What it holds is held to the same rule before it is repaired. Until the root has its
// own DACL it has %ProgramData%'s, under which Users may create folders in it, and a
// folder another account made there keeps that owner through the new DACL -- an owner
// can always grant itself the rest -- so the service would go on writing its log or its
// token into a place that account controls.
func secure(dir string) error {
	if chosen(dir) {
		if err := parents(dir); err != nil {
			return err
		}
	}

	owner, control, err := ownership(dir)
	if err != nil {
		return fmt.Errorf("read the ownership of %s: %w", dir, err)
	}

	admin := owner.Equals(sidSystem) || owner.Equals(sidAdmins)
	if admin && control&windows.SE_DACL_PROTECTED != 0 {
		return nil
	}

	if err := ownerRefusal(dir, owner); err != nil {
		return err
	}

	if err := filepath.WalkDir(dir, func(path string, _ fs.DirEntry, err error) error {
		if err != nil || path == dir || Trusted(path) {
			return err
		}

		return fmt.Errorf(
			"%s was made by another account before conflux secured %s, so conflux will not use it.\n"+
				"  Remove it, then run this again as Administrator", path, dir)
	}); err != nil {
		return err
	}

	return Restrict(dir, true)
}

// ownerRefusal is secure's refusal of dir for owner, or nil where owner is SYSTEM, the
// Administrators or the account running conflux.
func ownerRefusal(dir string, owner *windows.SID) error {
	if trusted(owner) {
		return nil
	}

	return fmt.Errorf(
		"%s belongs to %s, not to SYSTEM or the Administrators, so conflux did not create it and "+
			"will not use what is in it.\n  Remove it, then run this again as Administrator. If conflux left it, "+
			"run elevated by that same account, running any conflux command that way once repairs it; an "+
			"account that is not an administrator cannot",
		dir, accountName(owner))
}

// Foreign is what secure would refuse dir with for its owner, before anything is made, or
// nil where dir is this account's or is not there yet. A directory another account made is
// none of conflux's to use, and whoever reads one -- an ephemeral run's root, which /tmp lets
// anybody make first -- holds it to this as the conflux that makes one does.
func Foreign(dir string) error {
	owner, _, err := ownership(dir)
	if err != nil {
		return nil
	}

	return ownerRefusal(dir, owner)
}

// fileDeleteChild is FILE_DELETE_CHILD: on a directory, the right to delete or rename what
// is in it, whatever that grants.
const fileDeleteChild = 0x40

// moves is what an ACE on a directory above a root must not grant another account: to
// delete or rename what is in it, to delete or rename the directory itself, or to change
// who may. Creating folders in it is not among them: C:\ lets every user do that, and a
// folder of theirs cannot take the place of one that is not, as a sticky directory's
// cannot on Unix.
const moves = fileDeleteChild | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL

// sidTrustedInstaller is NT SERVICE\TrustedInstaller, which owns much of the system drive.
var sidTrustedInstaller, _ = windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")

// parents refuses dir where an account other than SYSTEM, Administrators, TrustedInstaller
// and the one running conflux may move it: one owns a directory above it, which lets it
// grant itself anything, or is granted one of moves on it. Whoever may move a parent can
// put a directory of their own where dir is, with a conflux in it for the service to run
// as SYSTEM. A link or junction on the way is held to the same, as itself, and the lookup
// goes on where it leads (ancestors).
func parents(dir string) error {
	above, err := ancestors(dir)
	if err != nil {
		return err
	}

	for _, p := range above {
		sd, err := ownSecurity(p)
		if err != nil {
			return fmt.Errorf("read the ownership of %s: %w", p, err)
		}

		owner, _, err := sd.Owner()
		if err != nil {
			return fmt.Errorf("read the owner of %s: %w", p, err)
		}

		dacl, _, err := sd.DACL()
		if err != nil {
			return fmt.Errorf("read the DACL of %s: %w", p, err)
		}

		who := ""

		switch {
		case !trustedOwner(owner):
			who = "belongs to " + accountName(owner) + ", who"
		case dacl == nil:
			who = "has no DACL, so anybody"
		default:
			if sid := mover(dacl); sid != nil {
				who = "grants " + accountName(sid) + " the right to move it or what is in it, who"
			}
		}

		if who != "" {
			return fmt.Errorf("%s is inside %s, which %s could move it aside and put another in its place "+
				"for conflux to run.\n  Choose a CONFLUX_DIR whose every parent only SYSTEM, the Administrators "+
				"and this account can change", dir, p, who)
		}
	}

	return nil
}

// ownSecurity is the owner and DACL of p itself: of a link or a junction, not of what it
// leads to.
func ownSecurity(p string) (*windows.SECURITY_DESCRIPTOR, error) {
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return nil, err
	}

	h, err := windows.CreateFile(name, windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)

	return windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
}

// isLink reports whether fi, read without following it, is a link a lookup follows: a
// symbolic link, or a junction or mount point, which Go reports as irregular rather than as
// a link or a directory.
func isLink(fi os.FileInfo) bool {
	return fi.Mode()&os.ModeSymlink != 0 || fi.Mode()&os.ModeIrregular != 0 && !fi.IsDir()
}

// mover is the first account dacl grants one of moves on the directory itself, other
// than those trustedOwner names, or nil.
func mover(dacl *windows.ACL) *windows.SID {
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, i, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Mask&moves == 0 {
			continue
		}

		if sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)); !trustedOwner(sid) {
			return sid
		}
	}

	return nil
}

// trustedOwner is whom trusted names, or TrustedInstaller: somebody who could change anything
// on the machine, or this conflux itself.
func trustedOwner(sid *windows.SID) bool {
	return trusted(sid) || sidTrustedInstaller != nil && sid.Equals(sidTrustedInstaller)
}

// accountName is sid as DOMAIN\account (SID), or the SID alone where it names nobody.
func accountName(sid *windows.SID) string {
	if account, domain, _, err := sid.LookupAccount(""); err == nil {
		return domain + "\\" + account + " (" + sid.String() + ")"
	}

	return sid.String()
}

func isCurrentUser(sid *windows.SID) bool {
	user := currentUser()

	return user != nil && user.Equals(sid)
}

// currentUser is the account this process runs as, read from its token once: Trusted asks
// for every file it checks, and the answer cannot change while the process runs.
var currentUser = sync.OnceValue(func() *windows.SID {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil
	}

	return user.User.Sid
})
