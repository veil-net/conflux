package paths

import (
	"encoding/binary"
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
// may not name Administrators as an owner, or change the owner at all -- one that is not
// elevated, which conflux never is outside a test -- keeps its own ownership and still gets
// the DACL. Protected is the half that matters for the DACL: without it the parent's ACEs
// are merged back in and the restriction is cosmetic.
func Restrict(path string, dir bool) error {
	return restrictWith(dir, func(owner *windows.SID, dacl *windows.ACL) error {
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, restrictInfo(owner), owner, nil, dacl, nil)
	})
}

// restrictWith gives something Restrict's security through set, handed the owner --
// Administrators, or nil to leave the owner as it is where the token may not name them -- and
// the DACL, which set protects.
func restrictWith(dir bool, set func(owner *windows.SID, dacl *windows.ACL) error) error {
	inherit := uint32(windows.NO_INHERITANCE)
	if dir {
		inherit = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}

	grant := func(sid *windows.SID, kind windows.TRUSTEE_TYPE) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: fileAllAccess,
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
		grant(sidSystem, windows.TRUSTEE_IS_USER),
		grant(sidAdmins, windows.TRUSTEE_IS_GROUP),
	}, nil)
	if err != nil {
		return err
	}

	err = set(sidAdmins, dacl)
	if errors.Is(err, windows.ERROR_INVALID_OWNER) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		err = set(nil, dacl)
	}

	return err
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

// makeRoot creates the root dir where it is not there yet, with Restrict's ownership and DACL
// set as it is made (makeRestricted), so that it never carries what %ProgramData% passes on --
// Users' right to create in it, enough to turn an empty directory into a junction -- not even for
// an instant. The directories above it are made as MkdirAll makes them. One already there is
// secure's.
func makeRoot(dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}

	if err := makeRestricted(dir); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}

	return nil
}

// makeRestricted is makeDir with Restrict's ownership and DACL: Administrators', or the creating
// token's where it may not name them, under a protected DACL granting SYSTEM and Administrators
// full control, inherited by what it holds.
func makeRestricted(path string) error {
	return restrictWith(true, func(owner *windows.SID, dacl *windows.ACL) error {
		sd, err := restrictedSD(owner, dacl)
		if err != nil {
			return err
		}

		return makeDir(path, sd)
	})
}

// makeDir creates the directory path, which must not be there yet, in a parent that is, with sd as
// its security descriptor, set as it is created: it is never anything else, not even for an
// instant, as one made and then given its security would be, under what its parent passes on.
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

// restrictedSD is a security descriptor of owner, where one is given, and dacl, protected: what
// restrictWith hands its set, for a directory being made.
func restrictedSD(owner *windows.SID, dacl *windows.ACL) (*windows.SECURITY_DESCRIPTOR, error) {
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, err
	}

	if owner != nil {
		if err := sd.SetOwner(owner, false); err != nil {
			return nil, err
		}
	}

	if err := sd.SetDACL(dacl, true, false); err != nil {
		return nil, err
	}

	if err := sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		return nil, err
	}

	return sd, nil
}

// fill makes the root held open by h hold something: its run directory, which EnsureAll makes
// there anyway, with Restrict's ownership and DACL set as it is created, made through h -- its
// name looked up in the directory h holds and nowhere else. A reparse point cannot be set on a
// directory that is not empty (FSCTL_SET_REPARSE_POINT fails with STATUS_DIRECTORY_NOT_EMPTY), so
// a handle somebody opened on the root before it was restricted, which keeps the rights it was
// opened with, can no longer make a junction of it, and the run directory, SYSTEM's and the
// Administrators', is not theirs to remove. Anything already there by that name does the same.
func fill(h windows.Handle) error {
	return restrictWith(true, func(owner *windows.SID, dacl *windows.ACL) error {
		sd, err := restrictedSD(owner, dacl)
		if err != nil {
			return err
		}

		name, err := windows.NewNTUnicodeString(runName)
		if err != nil {
			return err
		}

		oa := windows.OBJECT_ATTRIBUTES{
			Length:             uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
			RootDirectory:      h,
			ObjectName:         name,
			Attributes:         windows.OBJ_CASE_INSENSITIVE,
			SecurityDescriptor: sd,
		}

		var (
			child windows.Handle
			iosb  windows.IO_STATUS_BLOCK
		)

		err = windows.NtCreateFile(&child, windows.SYNCHRONIZE|windows.FILE_READ_ATTRIBUTES, &oa, &iosb, nil,
			windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			windows.FILE_CREATE, windows.FILE_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT,
			0, 0)

		var status windows.NTStatus

		switch {
		case err == nil:
			return windows.CloseHandle(child)
		case errors.As(err, &status) && status == windows.STATUS_OBJECT_NAME_COLLISION:
			return nil
		case errors.As(err, &status):
			return status.Errno() // so restrictWith tells a refused owner
		}

		return err
	})
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
// account made, a junction another account may point elsewhere (heldLink), or a CONFLUX_DIR
// another account can move (see parents).
//
// A directory conflux did not create is one somebody else may have filled before it
// looked -- with a binary for the service to run, or a manifest whose key they hold --
// and taking it over would adopt whatever is inside. The account running conflux is
// accepted as well as SYSTEM and Administrators: an administrator's own directory,
// under a policy that makes the creator its owner, is repaired rather than refused.
//
// The root is judged and restricted through one handle, opened on the directory itself and
// never by its name again (heldRoot): a name looked up afresh at each step could be a junction
// at the next, which Users may make of an empty directory they may write -- its own data or
// attributes are enough -- and which the named calls would follow, the ownership of where it
// leads answering for it and the restriction landing there. Once restricted, the root is made to
// hold something through the handle (fill), so that no handle opened on it earlier can make a
// junction of it afterwards, and read again through the handle: one that became a junction
// meanwhile is refused. A root whose DACL, as found, lets another account move what is in it is
// refused before that, since a handle opened under that grant could take out what fill puts there.
//
// What it holds is held to the same rule before it is repaired (contents). Until the root
// has its own DACL it has %ProgramData%'s, under which Users may create folders in it, and a
// folder another account made there keeps that owner through the new DACL -- an owner
// can always grant itself the rest -- so the service would go on writing its log or its
// token into a place that account controls.
func secure(dir string) error {
	root, err := heldRoot(dir, rootAccess)
	if err != nil {
		return err
	}
	defer root.close()

	if chosen(dir) {
		if err := parents(dir); err != nil {
			return err
		}
	}

	sd, err := security(root.dir)
	if err != nil {
		return fmt.Errorf("read the ownership of %s: %w", dir, err)
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read the owner of %s: %w", dir, err)
	}

	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("read the DACL of %s: %w", dir, err)
	}

	admin := owner.Equals(sidSystem) || owner.Equals(sidAdmins)
	if admin && control&windows.SE_DACL_PROTECTED != 0 {
		return nil
	}

	if err := ownerRefusal(dir, owner); err != nil {
		return err
	}

	// The root's own DACL, as found: fill holds a handle opened under it off only while nobody
	// else may take out what fill puts in the root, and a handle keeps what it was opened with
	// once the DACL is replaced. %ProgramData%'s grant to Users -- to add to a folder and write its
	// attributes -- moves nothing, so a root that only inherits it passes.
	switch who, _, err := changer(dir, root.dir, moves, "move it or what is in it", nil); {
	case err != nil:
		return err
	case who != "":
		return fmt.Errorf("%s %s could take out what conflux puts in it, with a handle opened now that keeps the "+
			"right once conflux restricts it, so conflux will not use it.\n  Remove that entry from its DACL, then "+
			"run this again as Administrator", dir, who)
	}

	if err := contents(dir); err != nil {
		return err
	}

	if err := restrictWith(true, func(owner *windows.SID, dacl *windows.ACL) error {
		return windows.SetSecurityInfo(root.dir, windows.SE_FILE_OBJECT, restrictInfo(owner), owner, nil, dacl, nil)
	}); err != nil {
		return fmt.Errorf("restrict %s: %w", dir, err)
	}

	restricted(dir)

	filled := fill(root.dir)

	if err := notLink(dir, root.dir, "became a junction or a link while conflux secured it"); err != nil {
		return err
	}

	if filled != nil {
		return fmt.Errorf("create %s in %s: %w", runName, dir, filled)
	}

	return nil
}

// restricted is called once secure has restricted a root through its handle, before it fills it
// and reads the handle again: nothing, but where a test turns the root into a junction meanwhile.
var restricted = func(string) {}

// rootAccess is what secure holds a root open for: to read its owner, DACL and attributes, and
// to replace its DACL and owner.
const rootAccess = windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES | windows.WRITE_DAC | windows.WRITE_OWNER

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

// Foreign is what secure would refuse dir with for its owner, for a junction another account
// may point elsewhere, or for anything in it another account may change (contents), before
// anything is made, or nil where dir is this account's or is not there yet. A directory another
// account made, or could have planted something in, is none of conflux's to use, and whoever
// reads one -- an ephemeral run's root, which %ProgramData% lets anybody make first -- holds it
// to this as the conflux that makes one does, through one handle as secure does, and reading
// alone: nothing is run from a root whose contents another account could have planted or can
// point elsewhere.
func Foreign(dir string) error {
	root, err := heldRoot(dir, readAccess)
	if errors.As(err, new(unopened)) {
		return nil
	}

	if err != nil {
		return err
	}
	defer root.close()

	sd, err := security(root.dir)
	if err != nil {
		return nil
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return nil
	}

	if err := ownerRefusal(dir, owner); err != nil {
		return err
	}

	return contents(dir)
}

// readAccess is what a handle that only reads who may change a file is opened for.
const readAccess = windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES

// held is a root held open: itself, as the lookup of its name found it, and the directory it
// is -- the same handle, or for a junction or a link heldLink holds, what it leads to.
type held struct{ self, dir windows.Handle }

func (r held) close() {
	if r.dir != r.self {
		windows.CloseHandle(r.dir)
	}

	windows.CloseHandle(r.self)
}

// heldRoot opens dir for access, as itself and never by its name again. A junction or a link is
// held to who may point it elsewhere (heldLink), as a link is on Unix to its owner, and judged
// through the handle that found it; where it is held, what it leads to is opened by following
// it, which nobody else may change meanwhile. Where the directory is that is not a plain
// directory either, it is refused: there is nothing further to follow. A root that could not be
// opened or read, or whose link leads nowhere, is refused as unopened.
func heldRoot(dir string, access uint32) (held, error) {
	self, err := openFile(dir, access, false)
	if err != nil {
		return held{}, fmt.Errorf("read %s: %w", dir, unopened{err})
	}

	r := held{self, self}

	link, err := isReparse(self)
	if err != nil {
		r.close()

		return held{}, fmt.Errorf("read %s: %w", dir, unopened{err})
	}

	if link {
		if err := heldLink(dir, self, nil); err != nil {
			r.close()

			return held{}, err
		}

		target, err := openFile(dir, access, true)
		if err != nil {
			r.close()

			return held{}, fmt.Errorf("read %s: %w", dir, unopened{err})
		}

		r.dir = target
	}

	if err := notLink(dir, r.dir, "leads to a reparse point conflux cannot follow"); err != nil {
		r.close()

		return held{}, err
	}

	return r, nil
}

// unopened is why heldRoot could not open or read a root: it is not there, or this account may
// not read it.
type unopened struct{ error }

func (u unopened) Unwrap() error { return u.error }

// notLink refuses dir, held open by h, where h is a reparse point -- a junction, a link, a mount
// point -- saying it is one as why does.
func notLink(dir string, h windows.Handle, why string) error {
	link, err := isReparse(h)
	switch {
	case err != nil:
		return fmt.Errorf("read %s: %w", dir, err)
	case link:
		return fmt.Errorf("%s %s, so conflux will not use it.\n  Remove it, then run this again as Administrator", dir, why)
	}

	return nil
}

// contents refuses the root dir where anything in it another account may change: each entry is
// judged by its own owner and DACL, read without following it, as mayChange reads them, and held
// to retargets, as a junction root is. A junction or a link another account may point elsewhere is
// refused, and not followed; so is anything else another account may write, move or point
// elsewhere -- a directory among them, which an account that may write its data or its attributes
// could make a junction of while it is empty, with a handle that keeps those rights once the
// restriction has replaced what the entry inherited.
//
// anchord's own account, this installation's service SID (ServiceSID), is conflux's, as the account
// anchord runs as is on Unix: what its DACL grants that SID is discounted, as SYSTEM's and the
// Administrators' grants are. Its owner is not: an entry the SID, or any account but SYSTEM, the
// Administrators, TrustedInstaller and the one running conflux, owns is refused, whatever its name,
// so one another account planted as anchor or run\anchord stays refused. A directory the DACL just
// judged lets that SID write -- anchor\ and run\anchord\, as makeAnchorDir makes them -- is not
// gone into: its DACL, which has just shown nobody else may write it, lets only SYSTEM, the
// Administrators and anchord make anything inside, and what anchord makes there, which it owns,
// conflux reads as anchord's, untrusted (OpenUntrusted, config.ReadUntrusted, copyTree).
func contents(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}

	if len(entries) == 0 {
		return nil
	}

	anchord, err := ServiceSID()
	if err != nil {
		return fmt.Errorf("judge what %s holds: %w", dir, err)
	}

	for _, e := range entries {
		if err := filepath.WalkDir(filepath.Join(dir, e.Name()), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			h, err := openFile(p, readAccess, false)
			if err != nil {
				return fmt.Errorf("read %s: %w", p, err)
			}
			defer windows.CloseHandle(h)

			link, err := isReparse(h)
			if err != nil {
				return fmt.Errorf("read %s: %w", p, err)
			}

			if link {
				if err := heldLink(p, h, anchord); err != nil || !d.IsDir() {
					return err
				}

				return fs.SkipDir // one listed as a directory a moment ago: not followed either
			}

			who, anchords, err := changer(p, h, retargets, "write it, move it or make a junction of it", anchord)
			switch {
			case err != nil:
				return err
			case who != "":
				return fmt.Errorf("%s, which %s could change it, is in %s, so conflux will not use it.\n"+
					"  Remove it, then run this again as Administrator", p, who, dir)
			case anchords && d.IsDir():
				return fs.SkipDir
			}

			return nil
		}); err != nil {
			return err
		}
	}

	return nil
}

// heldLink refuses dir, a junction or a link held open as itself by h, where an account other
// than those trustedOwner names, and anchord where it is given, may point it elsewhere: by owning
// it, or by a grant of retargets in its DACL. Owners and DACLs read by name follow a junction, so the directory it leads to
// would otherwise answer for it, and %ProgramData% lets any user make one where
// %ProgramData%\conflux or conflux-ephemeral is not yet, leading into a directory of SYSTEM's,
// and point it at one of their own once conflux has filled it, with a conflux.exe for the
// service to run as SYSTEM. Held as a link is on Unix, by its owner, and here by its DACL too.
func heldLink(dir string, h windows.Handle, anchord *windows.SID) error {
	who, _, err := changer(dir, h, retargets, "point it elsewhere or move it", anchord)
	if err != nil || who == "" {
		return err
	}

	return fmt.Errorf("%s is a junction or a link, which %s could point at a directory of their own, with a "+
		"conflux in it for the service to run.\n  Remove it, then run this again as Administrator", dir, who)
}

// openFile opens p for access: as itself, a link or a junction included, or, following, as
// whatever the lookup of its name leads to. Shared every way, so that nobody else's use of it
// is refused for conflux's look. A right to change the owner or the DACL that is not granted is
// given up rather than failing the open: a token that may not take ownership -- one that is not
// elevated, outside a test -- may still replace its own directory's DACL, a junction secure holds
// is only read, and a restriction through a handle without the right fails as it would by name.
func openFile(p string, access uint32, follow bool) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return 0, err
	}

	flags := uint32(windows.FILE_FLAG_BACKUP_SEMANTICS)
	if !follow {
		flags |= windows.FILE_FLAG_OPEN_REPARSE_POINT
	}

	h, err := windows.CreateFile(name, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, flags, 0)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		for _, right := range []uint32{windows.WRITE_OWNER, windows.WRITE_DAC} {
			if access&right != 0 {
				return openFile(p, access&^right, follow)
			}
		}
	}

	return h, err
}

// isReparse reports whether h is a reparse point: a junction, a link or a mount point, as
// itself.
func isReparse(h windows.Handle) (bool, error) {
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return false, err
	}

	return fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0, nil
}

// security is the owner and DACL of what h holds open.
func security(h windows.Handle) (*windows.SECURITY_DESCRIPTOR, error) {
	return windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
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

// retargets is what an ACE on a link or a junction, or on anything in a root, must not grant
// another account: moves, or a right that rewrites where it leads -- setting a reparse point takes FILE_WRITE_DATA or
// FILE_WRITE_ATTRIBUTES (MS-FSA 2.1.5.10.37) -- or GENERIC_WRITE, which holds both.
const retargets = moves | windows.FILE_WRITE_DATA | windows.FILE_WRITE_ATTRIBUTES | windows.GENERIC_WRITE

// sidTrustedInstaller is NT SERVICE\TrustedInstaller, which owns much of the system drive.
var sidTrustedInstaller, _ = windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")

// parents refuses dir where an account other than SYSTEM, Administrators, TrustedInstaller
// and the one running conflux may move it: one owns a directory above it, which lets it
// grant itself anything, or is granted one of moves on it. Whoever may move a parent can
// put a directory of their own where dir is, with a conflux in it for the service to run
// as SYSTEM. A link or junction on the way is held to the same, as itself, and to retargets,
// since whoever may point it elsewhere may as well; the lookup goes on where it leads
// (ancestors).
func parents(dir string) error {
	above, err := ancestors(dir)
	if err != nil {
		return err
	}

	for _, s := range above {
		p := s.path

		// A step the lookup reached without looking its name up is never a link (step).
		where, what, rights := "inside", "move it or what is in it", windows.ACCESS_MASK(moves)
		if s.fi != nil && isLink(s.fi) {
			where, what, rights = "reached through", "point it elsewhere or move it", retargets
		}

		who, err := mayChange(p, rights, what)
		if err != nil {
			return err
		}

		if who != "" {
			return fmt.Errorf("%s is %s %s, which %s could move it aside and put another in its place "+
				"for conflux to run.\n  Choose a CONFLUX_DIR whose every parent only SYSTEM, the Administrators "+
				"and this account can change", dir, where, p, who)
		}
	}

	return nil
}

// mayChange is who besides SYSTEM, the Administrators, TrustedInstaller and the account running
// conflux may change p itself, as a refusal names them, or "": changer, of p opened as itself.
func mayChange(p string, rights windows.ACCESS_MASK, what string) (string, error) {
	h, err := openFile(p, windows.READ_CONTROL, false)
	if err != nil {
		return "", fmt.Errorf("read the ownership of %s: %w", p, err)
	}
	defer windows.CloseHandle(h)

	who, _, err := changer(p, h, rights, what, nil)

	return who, err
}

// changer is who besides SYSTEM, the Administrators, TrustedInstaller and the account running
// conflux may change p, held open as itself by h, as a refusal names them, or "": its owner, who
// may grant itself anything, or anybody but anchord, where it is given, its DACL grants one of
// rights, which lets them what. anchords is whether the DACL grants anchord one of them.
func changer(p string, h windows.Handle, rights windows.ACCESS_MASK, what string,
	anchord *windows.SID) (who string, anchords bool, err error) {
	sd, err := security(h)
	if err != nil {
		return "", false, fmt.Errorf("read the ownership of %s: %w", p, err)
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return "", false, fmt.Errorf("read the owner of %s: %w", p, err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return "", false, fmt.Errorf("read the DACL of %s: %w", p, err)
	}

	switch {
	case !trustedOwner(owner):
		return "belongs to " + accountName(owner) + ", who", false, nil
	case dacl == nil:
		return "has no DACL, so anybody", false, nil
	}

	sid, anchords, err := mover(dacl, rights, anchord)
	switch {
	case err != nil:
		return "", false, fmt.Errorf("read the DACL of %s: %w", p, err)
	case sid != nil:
		return "grants " + accountName(sid) + " the right to " + what + ", who", anchords, nil
	}

	return "", anchords, nil
}

// isLink reports whether fi, read without following it, is a link a lookup follows: a
// symbolic link, or a junction or mount point, which Go reports as irregular rather than as
// a link or a directory.
func isLink(fi os.FileInfo) bool {
	return fi.Mode()&os.ModeSymlink != 0 || fi.Mode()&os.ModeIrregular != 0 && !fi.IsDir()
}

// mover is the first account dacl grants one of rights on the object itself, other than those
// trustedOwner names and anchord, where it is given, or nil; and whether it grants anchord one of
// them before it: each entry that allows rights on the object, as windowsGrants reads them.
func mover(dacl *windows.ACL, rights windows.ACCESS_MASK, anchord *windows.SID) (*windows.SID, bool, error) {
	header := unsafe.Slice((*byte)(unsafe.Pointer(dacl)), 8)

	grants, err := windowsGrants(unsafe.Slice((*byte)(unsafe.Pointer(dacl)), binary.LittleEndian.Uint16(header[2:])))
	if err != nil {
		return nil, false, err
	}

	anchords := false

	for _, g := range grants {
		if g.rights&uint32(rights) == 0 {
			continue
		}

		switch sid := (*windows.SID)(unsafe.Pointer(&g.sid[0])); {
		case anchord != nil && sid.Equals(anchord):
			anchords = true
		case !trustedOwner(sid):
			return sid, anchords, nil
		}
	}

	return nil, anchords, nil
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
