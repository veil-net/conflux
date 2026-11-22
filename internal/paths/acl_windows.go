package paths

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/veil-net/conflux/internal/privcheck"
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
// anything. A directory's grant is inherited by what it holds. WriteAtomic gives it to every
// private file it writes, while the file is still empty.
//
// The owner is set rather than left as it is (asAdministrators), so that a file conflux writes is the
// Administrators' whichever administrator's token wrote it, and no process of theirs that is not
// elevated can change it for the SYSTEM service to read. A token that may not name Administrators as
// an owner, or change the owner at all -- one that is not elevated, which no conflux command that
// writes in a root runs with, though a test may -- keeps its own ownership and still gets the DACL.
// Protected is the half that matters for the DACL: without it the parent's ACEs are merged back in
// and the restriction is cosmetic.
func Restrict(path string, dir bool) error {
	return restrictWith(dir, func(owner *windows.SID, dacl *windows.ACL) error {
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, restrictInfo(owner), owner, nil, dacl, nil)
	})
}

// restrictWith gives something Restrict's security through set, handed the owner --
// Administrators, or nil to leave the owner as it is where the token may not name them -- and
// the DACL, which set protects: SYSTEM and the Administrators full control, and nobody else
// anything.
func restrictWith(dir bool, set func(owner *windows.SID, dacl *windows.ACL) error) error {
	inherit := uint32(windows.NO_INHERITANCE)
	if dir {
		inherit = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}

	grant := func(sid *windows.SID, kind windows.TRUSTEE_TYPE, access windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: access,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inherit,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  kind,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}

	dacl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		grant(sidSystem, windows.TRUSTEE_IS_USER, fileAllAccess),
		grant(sidAdmins, windows.TRUSTEE_IS_GROUP, fileAllAccess),
	}, nil)
	if err != nil {
		return err
	}

	return asAdministrators(func(owner *windows.SID) error { return set(owner, dacl) })
}

// asAdministrators is how conflux names the owner of what it makes with a descriptor of its own -- a
// root, a folder in one, a folder on the way to one -- or restricts, a file it writes (Restrict): set,
// handed the Administrators, and, where the token may not name them -- one that is not elevated,
// which no conflux command that makes a root runs with, though a test may -- handed nil, to leave the
// owner as the token made it. Named rather than left to the token: a file made before it is
// restricted keeps the owner it has unless one is named, and the boot service, running as SYSTEM,
// trusts no account but the Administrators with its roots or the folders in them (ours). What is made
// is the Administrators' either way where the token is elevated
// (ElevatedDefaultOwner).
func asAdministrators(set func(owner *windows.SID) error) error {
	err := set(sidAdmins)
	if errors.Is(err, windows.ERROR_INVALID_OWNER) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		err = set(nil)
	}

	return err
}

// ElevatedDefaultOwner makes the Administrators the owner this process's token gives what it makes
// without naming one, where the token is elevated, as the first thing every conflux process does: so
// what it makes by its name in a root -- the lock files, bin\ and its lock, the service's copy of
// conflux, the log -- is the Administrators' from the moment it exists,
// and a CREATOR OWNER entry it inherits grants them, whatever the machine's default-owner policy
// says. That policy makes what an elevated administrator makes the Administrators' on Windows Server
// and that administrator's own on a Windows client, whose unelevated processes could then change it
// for the boot service, running as SYSTEM, to read or run. A token that is not elevated is left as it
// is: it may not name the Administrators, and no conflux command that makes a root runs without
// elevation. SYSTEM's, the service's, is elevated, and holds the Administrators too.
//
// privtest writes the token's owner itself as well (setDefaultOwner, for CreatorOwns, which names
// the token's user): it imports nothing of conflux's, since paths' own tests import it, so it cannot
// call this.
func ElevatedDefaultOwner() error {
	if !privcheck.Elevated() {
		return nil
	}

	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_QUERY,
		&tok); err != nil {
		return fmt.Errorf("make the Administrators the owner of what conflux makes: %w", err)
	}
	defer tok.Close()

	owner := struct{ sid *windows.SID }{sidAdmins} // TOKEN_OWNER

	if err := windows.SetTokenInformation(tok, windows.TokenOwner, (*byte)(unsafe.Pointer(&owner)),
		uint32(unsafe.Sizeof(owner))); err != nil {
		return fmt.Errorf("make the Administrators the owner of what conflux makes: %w", err)
	}

	return nil
}

// fileAllAccess is FILE_ALL_ACCESS, full control of a file or a directory: specific rights rather
// than GENERIC_ALL, so a DACL given as a directory is created holds what it says with nothing left
// to map.
const fileAllAccess = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff

// restrictInfo is what a restriction with owner writes: the DACL, protected, and the owner where
// one is given.
func restrictInfo(owner *windows.SID) windows.SECURITY_INFORMATION {
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if owner != nil {
		info |= windows.OWNER_SECURITY_INFORMATION
	}

	return info
}

// aLink is what makeWay calls a link made where it was making a folder.
const aLink = "a junction or a link"

// step is a folder, or a junction or a link, a walk holds open as itself.
type step struct{ h windows.Handle }

func (s step) close() { windows.CloseHandle(s.h) }

// openTop holds the top of the volume vol open -- a drive (C:), a volume by its GUID, or a share
// (\\host\share) -- to read who may change it, as itself and shared every way, so that nobody else's
// use of it is refused for conflux's look; and refuses it where it is on a network volume (remote):
// who owns what is there, and whom its DACLs grant, are accounts of the machine serving it, which this
// one cannot judge, so nothing is judged, looked up or made there.
func openTop(vol string) (step, error) {
	top := vol + `\`

	name, err := windows.UTF16PtrFromString(top)
	if err != nil {
		return step{}, fmt.Errorf("read %s: %w", top, err)
	}

	h, err := windows.CreateFile(name, readAccess, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return step{}, fmt.Errorf("read %s: %w", top, err)
	}

	if err := remote(top, h); err != nil {
		windows.CloseHandle(h)

		return step{}, err
	}

	return step{h}, nil
}

// lookAt is what is at name in the folder parent holds open, held open as itself to read who may change
// it, and its kind -- a junction or a link (a name surrogate, as nameSurrogate reads one), a folder, or
// anything else, a file -- by its attributes: looked up there and nowhere else, never followed, nor
// reparsed anywhere (ntOpen). Nothing at the name is an error that is fs.ErrNotExist.
func lookAt(parent step, name string) (step, kind, error) {
	h, err := ntOpen(parent.h, name, nil, windows.SYNCHRONIZE|readAccess, windows.FILE_OPEN, 0)
	if err != nil {
		return step{}, isOther, err
	}

	attributes, tag, err := attributeTag(h)

	switch {
	case err != nil:
		windows.CloseHandle(h)

		return step{}, isOther, err
	case attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 && tag&reparseTagNameSurrogate != 0:
		return step{h}, isLink, nil
	case attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0:
		return step{h}, isFolder, nil
	}

	return step{h}, isFile, nil
}

// lookUp is the folder, or the junction or link, at name in the folder parent holds open (lookAt), and
// whether it is a junction or a link. Anything else there is refused as errNotDir, and nothing at the
// name is an error that is fs.ErrNotExist.
func lookUp(parent step, name string) (step, bool, error) {
	s, k, err := lookAt(parent, name)
	if err == nil && k == isFile {
		s.close()

		return step{}, false, errNotDir
	}

	return s, k == isLink, err
}

// readLink is where the junction or link s holds open leads, read off it (linkTarget): one that may
// lead off this machine is refused unfollowed.
func readLink(s step) (string, error) { return linkTarget(s.h) }

// makeStep makes the folder name in the one parent holds open, and holds it open: through parent
// (createIn), looked up there and nowhere else and never followed, with Restrict's ownership and
// DACL set as it is created, a folder on the way to the root exactly as the root, rather than what
// the one before passes on: in C:\ Authenticated Users' right to delete it, and its owner the
// administrator who ran conflux, whom the SYSTEM service does not trust. The way conflux makes is
// then its own, as the 0700 directories it makes on Unix are, and grants nobody else anything, and the
// root it makes is as conflux makes one (ours). ERROR_ALREADY_EXISTS is anything already at the name, a link included.
func makeStep(parent step, name string) (step, bool, error) {
	h, err := createIn(parent.h, name, windows.SYNCHRONIZE|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return step{}, false, err
	}

	return step{h}, true, nil
}

// linkTarget is where the symbolic link or junction h holds open as itself leads, read off the link
// (FSCTL_GET_REPARSE_POINT) and not by following it (windowsLinkTarget): one that may lead off this
// machine is refused unfollowed.
func linkTarget(h windows.Handle) (string, error) {
	b := make([]byte, windows.MAXIMUM_REPARSE_DATA_BUFFER_SIZE)

	var n uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_GET_REPARSE_POINT, nil, 0, &b[0], uint32(len(b)), &n,
		nil); err != nil {
		return "", err
	}

	return windowsLinkTarget(b[:n])
}

// MakeRestricted is makeDir with Restrict's ownership and DACL: Administrators', or the creating
// token's where it may not name them, under a protected DACL granting SYSTEM and Administrators
// full control, inherited by what it holds.
func MakeRestricted(path string) error {
	return restrictedDir(func(sd *windows.SECURITY_DESCRIPTOR) error { return makeDir(path, sd) })
}

// MakeAnchordDir is makeDir with anchordDirSDDL: a directory anchord's account, the service SID sid,
// is given -- anchor\ and run\anchord\ where anchord runs as that account.
func MakeAnchordDir(path string, sid *windows.SID) error {
	sd, err := windows.SecurityDescriptorFromString(anchordDirSDDL(sid))
	if err != nil {
		return err
	}

	return makeDir(path, sd)
}

// anchordDirSDDL is the security descriptor of a directory anchord's account, the service SID sid,
// is given: SYSTEM's, under a protected
// DACL granting SYSTEM and the Administrators full control of it and of what it holds; sid, on the
// directory itself, the right to list and traverse it, create files and subdirectories in it,
// delete what is in it and read and write its attributes -- 0x1201ff, and not DELETE, WRITE_DAC or
// WRITE_OWNER on it -- and full control of what it holds; and an OWNER RIGHTS entry granting an
// owner only READ_CONTROL, so that owning a file grants nothing.
func anchordDirSDDL(sid *windows.SID) string {
	s := sid.String()

	return "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1201ff;;;" + s + ")" +
		"(A;OICIIO;FA;;;" + s + ")(A;OICI;RC;;;OW)"
}

// makeDir creates the directory path, which must not be there yet, in a parent that is, with sd as
// its security descriptor, set as it is created: it is never anything else, not even for an
// instant, as one made and then given its security would be, under what its parent passes on.
// libexec's staging directory (MakeRestricted) and the directories anchord is given (daemon's
// makeAnchorDir: MakeRestricted, or MakeAnchordDir for its account) are made so; a root and its
// run directory are made the same way through a handle on their parent (createIn).
func makeDir(path string, sd *windows.SECURITY_DESCRIPTOR) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	return windows.CreateDirectory(name, &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	})
}

// restrictedDir makes a directory through create, handed the security descriptor to create it
// with: Restrict's ownership and DACL -- restrictWith's owner, where one is given, and its DACL,
// protected -- and, where the token may not name Administrators as its owner, again without one.
// What create fails with is returned as it is, ERROR_ALREADY_EXISTS for a name already taken
// among it.
func restrictedDir(create func(sd *windows.SECURITY_DESCRIPTOR) error) error {
	return restrictWith(true, func(owner *windows.SID, dacl *windows.ACL) error {
		sd, err := windows.NewSecurityDescriptor()
		if err != nil {
			return err
		}

		if owner != nil {
			if err := sd.SetOwner(owner, false); err != nil {
				return err
			}
		}

		if err := sd.SetDACL(dacl, true, false); err != nil {
			return err
		}

		if err := sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
			return err
		}

		return create(sd)
	})
}

// createIn creates the directory name in the one parent holds open, with Restrict's ownership and
// DACL set as it is created (restrictedDir), and holds it open for access: its name looked up there
// and nowhere else, and never followed (ntOpen's FILE_OPEN_REPARSE_POINT), so ERROR_ALREADY_EXISTS
// is anything at the name, a link included. The create is also kept from being reparsed anywhere
// (ntOpen's OBJ_DONT_REPARSE), so that a parent that became a junction or a mount point after it was
// opened would fail it rather than take it to where it leads: defence in depth, guarding a case not
// shown to happen, since a create relative to a held directory is not known to be reparsed through
// it without the flag either. A status NtCreateFile fails with is the Win32 error it maps to, as
// CreateDirectory returns one, so that restrictWith tells a refused owner.
func createIn(parent windows.Handle, name string, access uint32) (windows.Handle, error) {
	var h windows.Handle

	err := restrictedDir(func(sd *windows.SECURITY_DESCRIPTOR) (err error) {
		h, err = ntOpen(parent, name, sd, access, windows.FILE_CREATE, windows.FILE_DIRECTORY_FILE)

		return err
	})

	return h, err
}

// ntOpen is createIn and lookUp's open: NtCreateFile of name relative to parent, as disposition
// says, with options beside never following what is at the name, and sd where it creates one.
func ntOpen(parent windows.Handle, name string, sd *windows.SECURITY_DESCRIPTOR, access, disposition,
	options uint32) (windows.Handle, error) {
	u, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}

	oa := windows.OBJECT_ATTRIBUTES{
		Length:             uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory:      parent,
		ObjectName:         u,
		Attributes:         windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
		SecurityDescriptor: sd,
	}

	var (
		h    windows.Handle
		iosb windows.IO_STATUS_BLOCK
	)

	err = windows.NtCreateFile(&h, access, &oa, &iosb, nil,
		windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		disposition, options|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT,
		0, 0)

	if status, ok := err.(windows.NTStatus); ok {
		return h, status.Errno()
	}

	return h, err
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
// running conflux -- by somebody who could have written it anyway. Whoever else owns it
// can grant themselves the right to change it: a CA directory (pki/ca) found with such an
// owner is not used.
func Trusted(path string) bool {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}

	owner, _, err := sd.Owner()

	return err == nil && trusted(owner)
}

// trusted is SYSTEM, Administrators or the account running conflux: somebody who could have
// written anything conflux did.
func trusted(sid *windows.SID) bool {
	return sid.Equals(sidSystem) || sid.Equals(sidAdmins) || isCurrentUser(sid)
}

// ours is why what s holds open -- a folder, at the root dir's name or a folder's in one, or a file in one
// -- is not as conflux makes it, or "" where it is: owned by SYSTEM, the Administrators, TrustedInstaller
// or the account it is judged for, and its DACL granting nobody else any right, to read it included, on it
// or on what is made in it (changerIn), as read through s. An installation's root, which the
// boot service runs from as SYSTEM, trusting no other account, is judged for SYSTEM; an ephemeral run's
// for the Administrators (judgedFor). %ProgramData% lets any account make a folder at a name not taken
// yet, which keeps that account as its owner, or inherits Users' grants from it: neither is ours.
func ours(dir string, s step, installation bool) (string, error) {
	sd, err := security(s.h)
	if err != nil {
		return "", fmt.Errorf("read the ownership of %s: %w", dir, err)
	}

	who, err := changerIn(dir, judgedFor(installation), sd)
	if who != "" {
		who += " could change it or read what is in it"
	}

	return who, err
}

// judgedFor is the account a root, and what it holds, is judged for: SYSTEM, which the boot service
// runs as, for an installation's (installation), and the Administrators for an ephemeral run's, which
// only an elevated conflux makes or can open. Never the account running conflux by its own SID: what
// that account owns, or is granted, its processes that are not elevated may change -- a root
// %ProgramData% let them make first, with a held lock, a readiness marker and an anchorctl of their own
// in it -- for an elevated conflux to read and run.
func judgedFor(installation bool) *windows.SID {
	if installation {
		return sidSystem
	}

	return sidAdmins
}

// dispose removes what h holds open, opened with DELETE: with POSIX semantics where the file system
// has them, so the name is gone at once, though somebody else holds it open, read-only or not where
// Windows lets the attribute be passed over (1809 on), and otherwise once every handle on it is
// closed.
func dispose(h windows.Handle) error {
	unsupported := func(err error) bool {
		return errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_INVALID_FUNCTION) ||
			errors.Is(err, windows.ERROR_NOT_SUPPORTED)
	}

	for _, flags := range []uint32{
		windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_POSIX_SEMANTICS |
			windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
		windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_POSIX_SEMANTICS,
	} {
		if err := windows.SetFileInformationByHandle(h, windows.FileDispositionInfoEx, (*byte)(unsafe.Pointer(&flags)),
			uint32(unsafe.Sizeof(flags))); !unsupported(err) {
			return err
		}
	}

	del := byte(1) // FILE_DISPOSITION_INFO's DeleteFile

	return windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &del, 1)
}

// readAccess is what a handle that only reads who may change a file is opened for.
const readAccess = windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES

// remote refuses dir, whose directory h holds open, where that is on a network volume -- a share
// reached by its UNC path, a drive mapped to one, or a link leading to either -- as the device the
// volume is on says of itself (FILE_FS_DEVICE_INFORMATION, which GetDriveType reads DRIVE_REMOTE
// from), and not as dir is spelled. Who owns what is there, and whom its DACL grants, are the
// accounts of the machine serving it -- its Administrators are not this machine's -- which this one
// cannot judge.
func remote(dir string, h windows.Handle) error {
	var (
		info struct{ deviceType, characteristics uint32 } // FILE_FS_DEVICE_INFORMATION
		iosb windows.IO_STATUS_BLOCK
	)

	r, _, _ := ntQueryVolumeInformationFile.Call(uintptr(h), uintptr(unsafe.Pointer(&iosb)),
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info), fileFsDeviceInformation)
	if status := windows.NTStatus(r); status != windows.STATUS_SUCCESS {
		return fmt.Errorf("read the volume %s is on: %w", dir, status.Errno())
	}

	switch {
	case info.characteristics&fileRemoteDevice != 0:
	case info.deviceType == fileDeviceNetwork, info.deviceType == fileDeviceNetworkFileSystem,
		info.deviceType == fileDeviceMultiUNCProvider, info.deviceType == fileDeviceDFS,
		info.deviceType == fileDeviceDFSFileSystem, info.deviceType == fileDeviceDFSVolume:
	default:
		return nil
	}

	return fmt.Errorf("%s is on a network volume, or leads to one, so conflux will not use it: who owns what is "+
		"there, and whom its DACL grants, are accounts of the machine serving it, which this one cannot judge.\n"+
		"  Keep it on a volume of this machine's own, then run this again as Administrator", dir)
}

// ntQueryVolumeInformationFile is ntdll's: what the volume a handle is open on says of itself.
var ntQueryVolumeInformationFile = ntdll.NewProc("NtQueryVolumeInformationFile")

// ntdll is the native API, whose calls x/sys does not all wrap.
var ntdll = windows.NewLazySystemDLL("ntdll.dll")

// What FILE_FS_DEVICE_INFORMATION says of a volume on another machine: FileFsDeviceInformation, the
// class that asks for it; FILE_REMOTE_DEVICE, a characteristic of the device; and the device types
// of a network, its redirectors, the provider of UNC names and DFS.
const (
	fileFsDeviceInformation = 4

	fileRemoteDevice = 0x10

	fileDeviceDFS               = 0x06
	fileDeviceMultiUNCProvider  = 0x10
	fileDeviceNetwork           = 0x12
	fileDeviceNetworkFileSystem = 0x14
	fileDeviceDFSFileSystem     = 0x35
	fileDeviceDFSVolume         = 0x36
)

// openIn opens name, a file in the folder s holds open, which p names, to read: looked up there and
// nowhere else, never followed (ntOpen), a reparse point opened as itself, which PlainFile refuses.
func openIn(s step, name, p string) (*os.File, error) {
	h, err := ntOpen(s.h, name, nil, windows.GENERIC_READ|windows.SYNCHRONIZE, windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: p, Err: err}
	}

	return os.NewFile(uintptr(h), p), nil
}

// attributeTag is what h holds open's attributes and, where it is a reparse point, its tag say
// (FILE_ATTRIBUTE_TAG_INFO).
func attributeTag(h windows.Handle) (attributes, tag uint32, err error) {
	var info struct{ FileAttributes, ReparseTag uint32 }
	if err := windows.GetFileInformationByHandleEx(h, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info))); err != nil {
		return 0, 0, err
	}

	return info.FileAttributes, info.ReparseTag, nil
}

// reparseTagNameSurrogate is the bit of a reparse tag that says it stands for another name.
const reparseTagNameSurrogate = 0x20000000

// security is the owner and DACL of what h holds open.
func security(h windows.Handle) (*windows.SECURITY_DESCRIPTOR, error) {
	return windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
}

// sidCreatorOwner is CREATOR OWNER, which an entry passed on grants whoever makes what it is passed
// to, and which grants nobody anything on the object itself.
var sidCreatorOwner = wellKnown(windows.WinCreatorOwnerSid)

// sidTrustedInstaller is NT SERVICE\TrustedInstaller, which owns much of the system drive.
var sidTrustedInstaller, _ = windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")

// changerIn is who besides SYSTEM, the Administrators, TrustedInstaller and self, the account the
// judgement is made for (trustedFor), may change p, whose owner and DACL sd holds, as a refusal
// names them, or "": its owner, who may grant itself anything, or anybody its DACL grants any right,
// on p itself or on what is made in it (mover) -- to read it among them, since what it holds inherits
// that: a lock file an account let read may hold against the supervisor (flock.Held), and the
// service's log.
func changerIn(p string, self *windows.SID, sd *windows.SECURITY_DESCRIPTOR) (string, error) {
	owner, _, err := sd.Owner()
	if err != nil {
		return "", fmt.Errorf("read the owner of %s: %w", p, err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return "", fmt.Errorf("read the DACL of %s: %w", p, err)
	}

	switch {
	case !trustedFor(owner, self):
		return "belongs to " + accountName(owner) + ", who", nil
	case dacl == nil:
		return "has no DACL, so anybody", nil
	}

	sid, err := mover(dacl, self)
	switch {
	case err != nil:
		return "", fmt.Errorf("read the DACL of %s: %w", p, err)
	case sid != nil:
		return "grants " + accountName(sid) + " the right to use it or what is made in it, who", nil
	}

	return "", nil
}

// mover is the first account dacl grants any right on the object itself or on what is made in it,
// other than those trustedFor names for self, or nil: each entry that allows a right there, as
// windowsGrants reads them. CREATOR OWNER is nobody on the object itself, and passed on, whoever made
// what it is passed to, whom this same judgement holds to the accounts trustedFor names: so it is
// counted as the account running conflux, the one whose making conflux can answer for -- what an
// administrator makes is their own under a Windows client's default-owner policy -- and passes only
// where that account is trusted for self. A judgement for SYSTEM made by an administrator's run, an
// installation's root's, counts it as that administrator, so such a root is not as conflux makes one,
// and EnsureAll makes it afresh.
func mover(dacl *windows.ACL, self *windows.SID) (*windows.SID, error) {
	header := unsafe.Slice((*byte)(unsafe.Pointer(dacl)), 8)

	grants, err := windowsGrants(unsafe.Slice((*byte)(unsafe.Pointer(dacl)), binary.LittleEndian.Uint16(header[2:])))
	if err != nil {
		return nil, err
	}

	for _, g := range grants {
		if g.rights == 0 {
			continue
		}

		switch sid := (*windows.SID)(unsafe.Pointer(&g.sid[0])); {
		case sid.Equals(sidCreatorOwner):
			// Nobody on the object itself, and on what it is passed to whoever made that: the account
			// running conflux, unless a trusted one.
			switch user := currentUser(); {
			case user == nil:
				return sid, nil
			case !trustedFor(user, self):
				return user, nil
			}
		case !trustedFor(sid, self):
			return sid, nil
		}
	}

	return nil, nil
}

// trustedFor is SYSTEM, the Administrators, TrustedInstaller or self, where self is known: somebody
// who could change anything on the machine, or the account a judgement is made for (judgedFor).
func trustedFor(sid, self *windows.SID) bool {
	return sid.Equals(sidSystem) || sid.Equals(sidAdmins) || self != nil && sid.Equals(self) ||
		sidTrustedInstaller != nil && sid.Equals(sidTrustedInstaller)
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

// currentUser is the account this process runs as, read from its token once: the judgements of
// roots ask for it of each folder and file they hold, and the answer cannot change while the
// process runs.
var currentUser = sync.OnceValue(func() *windows.SID {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil
	}

	return user.User.Sid
})
