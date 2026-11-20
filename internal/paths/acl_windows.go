package paths

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf16"
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
// set as it is made (MakeRestricted), so that it never carries what %ProgramData% passes on --
// Users' right to create in it, enough to turn an empty directory into a junction -- not even for
// an instant. The directories above it are made as MkdirAll makes them. One already there is
// secure's.
func makeRoot(dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}

	if err := MakeRestricted(dir); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}

	return nil
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
// is given, which contents does not go into once its DACL is judged: SYSTEM's, under a protected
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
// instant, as one made and then given its security would be, under what its parent passes on. A
// root (makeRoot, through MakeRestricted), libexec's staging directory (MakeRestricted) and the
// directories anchord is given (daemon's makeAnchorDir: MakeRestricted, or MakeAnchordDir for its
// account) are made so.
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

// fill makes the root dir, held open by h, hold something -- its run directory, which EnsureAll
// makes there anyway, with Restrict's ownership and DACL set as it is created, made through h: its
// name looked up in the directory h holds and nowhere else -- and reads h again: one that became a
// junction or a link before then is refused. A reparse point cannot be set on a directory that is
// not empty (FSCTL_SET_REPARSE_POINT fails with STATUS_DIRECTORY_NOT_EMPTY), so a handle somebody
// opened on the root while its DACL let them write it, which keeps the rights it was opened with,
// can no longer make a junction of it, and the run directory, SYSTEM's and the Administrators', is
// not theirs to remove. Anything already there by that name does the same, and is judged with the
// rest of what the root holds (contents). A root whose DACL does not let this account create a
// folder in it is refused, saying so: it is filled before anything else, its DACL as found.
func fill(dir string, h windows.Handle) error {
	filling(dir)

	filled := restrictedDir(func(sd *windows.SECURITY_DESCRIPTOR) error {
		child, err := createDir(h, runName, sd, windows.SYNCHRONIZE|windows.FILE_READ_ATTRIBUTES)
		if err != nil {
			return err
		}

		return windows.CloseHandle(child)
	})

	if err := notLink(dir, h, "became a junction or a link while conflux secured it"); err != nil {
		return err
	}

	switch {
	case filled == nil, errors.Is(filled, windows.ERROR_ALREADY_EXISTS):
		return nil
	case errors.Is(filled, windows.ERROR_ACCESS_DENIED):
		return fmt.Errorf("conflux could not add %s to %s, whose DACL does not let this account create a folder in "+
			"it: conflux adds %s before it judges or restricts a root, so that no handle opened on the root earlier "+
			"can make a junction of it.\n  Give SYSTEM and the Administrators full control of %s, then run this "+
			"again as Administrator", runName, dir, runName, dir)
	}

	return fmt.Errorf("create %s in %s: %w", runName, dir, filled)
}

// filling is called before secure fills a root: nothing, but where a test turns the root into a
// junction meanwhile.
var filling = func(string) {}

// createDir creates the directory name in the one parent holds open, with sd as its security
// descriptor, and holds it open for access: its name looked up there and nowhere else, and never
// followed. A status NtCreateFile fails with is returned as the Win32 error it maps to, as
// CreateDirectory returns one -- ERROR_ALREADY_EXISTS for a name already taken -- so that
// restrictWith tells a refused owner.
func createDir(parent windows.Handle, name string, sd *windows.SECURITY_DESCRIPTOR, access uint32) (windows.Handle, error) {
	u, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}

	oa := windows.OBJECT_ATTRIBUTES{
		Length:             uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory:      parent,
		ObjectName:         u,
		Attributes:         windows.OBJ_CASE_INSENSITIVE,
		SecurityDescriptor: sd,
	}

	var (
		h    windows.Handle
		iosb windows.IO_STATUS_BLOCK
	)

	err = windows.NtCreateFile(&h, access, &oa, &iosb, nil,
		windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_CREATE, windows.FILE_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT,
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
// running conflux -- by somebody who could have written it anyway. Restrict makes
// Administrators the owner of everything conflux writes, so another owner is another
// account's file, and whoever owns a file can grant themselves the right to change it:
// a binary about to run as SYSTEM, found with such an owner, is not run.
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

// secure gives a conflux root its ownership and DACL, once, and refuses one another
// account made, a junction another account may point elsewhere (heldLink), or a CONFLUX_DIR
// another account can move (see parents). A root secured already -- SYSTEM's or the
// Administrators', under a protected DACL that grants nobody else a right retargets names, on the
// root or on what is made in it -- is not restricted again, but it is filled as any root is (fill),
// and what it holds is judged again (contents), so that what a run refused once the root was
// restricted is refused by every run after; one protected that grants more, or passes more on, or
// has no DACL at all, is held to all of what follows, as one found unrestricted is.
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
// leads answering for it and the restriction landing there. A root that is a junction is held as a
// symlinked root is on Unix, to who may point it elsewhere, and replaced with a junction of
// conflux's own leading to the directory judged (replaceLink), since a handle opened on it while
// its DACL let somebody write it could repoint it in place. Then, before anything the root holds is
// judged, it is made to hold something through the handle (fill), so that no handle opened on it
// earlier can make a junction of it afterwards, whatever secure goes on to decide, a refusal
// included, and read again through the handle: one that became a junction meanwhile is refused. A
// root whose DACL, as found, lets another account move what is in it is refused before either,
// since a handle opened under that grant could take out what fill puts there.
//
// What it holds is held to the same rule (contents): before it is repaired, as it was found, what
// each thing inherits from the root included -- a handle opened under an inherited grant keeps it
// once the restriction has replaced it -- and again once the root is restricted. Until the root
// has its own DACL it has %ProgramData%'s, under which Users may create folders in it, the moment
// between the first look and the restriction included, and a folder another account made there
// keeps that owner through the new DACL -- an owner can always grant itself the rest -- so the
// service would go on writing its log or its token into a place that account controls.
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

	// Secured already: SYSTEM's or the Administrators', under a protected DACL that lets nobody else
	// write it, move it or change who may, nor passes such a right on to what is made in it -- what a
	// restriction leaves -- and, where the root is a junction, the junction SYSTEM's or the
	// Administrators' under a protected DACL too, as replaceLink leaves one. It is not restricted
	// again, but it is filled, since one secured and empty -- as an administrator may have restricted
	// it -- is as open to a handle opened on it before as one found unrestricted, and what it holds is
	// judged as it is once a root is restricted: a restriction refused by that judgement is still in
	// place, and what it refused is still there. A protected DACL that grants more, or passes more on
	// -- to logs\, which EnsureAll then makes in the root by its name, and the service writes in
	// before any run judges it -- or none at all, or a junction conflux did not make, is repaired,
	// replaced or refused below as an unrestricted root is.
	if secured(sd) && (root.link == nil || secured(root.link)) {
		switch who, _, err := changerIn(dir, sd, retargets, "write it or what is made in it", nil, true); {
		case err != nil:
			return err
		case who == "":
			// Taken as conflux's, a link leads where one of conflux's could: never to a network share.
			if root.link != nil {
				if _, err := leadsTo(dir, root.dir); err != nil {
					return err
				}
			}

			if err := fill(dir, root.dir); err != nil {
				return err
			}

			return contents(dir)
		}
	}

	if err := ownerRefusal(dir, owner); err != nil {
		return err
	}

	// The root's own DACL, as found: fill holds a handle opened under it off only while nobody
	// else may take out what fill puts in the root, and a handle keeps what it was opened with
	// once the DACL is replaced. %ProgramData%'s grant to Users -- to add to a folder and write its
	// attributes -- moves nothing, so a root that only inherits it passes.
	if err := moverRefusal(dir, sd, "take out what conflux puts in it, with a handle opened now that keeps the "+
		"right once conflux restricts it"); err != nil {
		return err
	}

	// A junction is made conflux's own before what the root holds is read by its name, through it.
	if root.link != nil {
		if err := replaceLink(dir, &root); err != nil {
			return err
		}
	}

	// Filled before anything is judged, so that no refusal below leaves the root empty, restricted
	// or not, for a handle opened on it earlier to make a junction of.
	if err := fill(dir, root.dir); err != nil {
		return err
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

	return contents(dir)
}

// secured reports whether sd is owned and protected as a restriction leaves it: SYSTEM's or the
// Administrators', its DACL protected.
func secured(sd *windows.SECURITY_DESCRIPTOR) bool {
	owner, _, err := sd.Owner()
	if err != nil || !owner.Equals(sidSystem) && !owner.Equals(sidAdmins) {
		return false
	}

	control, _, err := sd.Control()

	return err == nil && control&windows.SE_DACL_PROTECTED != 0
}

// replaceLink makes dir, a junction or a link r holds open as itself, a junction of conflux's own
// leading to r.dir, the directory secure judged: the one found is removed, at once though others
// hold it open, and another made at its name through a handle of conflux's, created with
// Restrict's ownership and DACL -- so nobody else can ever have opened it to write -- and given
// r.dir as its reparse point through that handle. A handle somebody opened on the one found,
// which keeps the rights it was opened with, can repoint nothing anybody reaches by the name.
// Something made at the name before conflux makes its own is refused, naming where the junction
// led and saying to make it again first: with nothing at the name, the next run would make a root
// afresh there, and the machine a new identity. A failure to make or point its own says the same;
// a kill in that instant says nothing, and leaves conflux's empty directory at the name, which
// windows.md tells an operator to make the junction again in place of. So is a directory that
// cannot be named by its volume, a network share's, which a junction cannot lead to. r.self is
// the new junction after.
func replaceLink(dir string, r *held) error {
	target, err := leadsTo(dir, r.dir)
	if err != nil {
		return err
	}

	shown, _ := finalPath(r.dir, volumeNameDOS) // what dir shows it leads to; nothing where it has no such name
	shown = strings.TrimPrefix(shown, `\\?\`)

	// The way on from a refusal once the junction found is gone: the junction made again, to where
	// it led, by its drive letter where it has one.
	leads := shown
	if leads == "" {
		leads = target
	}

	remake := `Remove whatever is at its name and make the junction again, mklink /J "` + dir + `" "` + leads +
		`", then run this again as Administrator; with nothing there, conflux would make a new root, and the ` +
		"machine a new identity"

	parent, err := openFile(filepath.Dir(dir), windows.FILE_READ_ATTRIBUTES, true)
	if err != nil {
		return fmt.Errorf("read %s: %w", filepath.Dir(dir), err)
	}
	defer windows.CloseHandle(parent)

	if err := unlink(dir, r.self); err != nil {
		return fmt.Errorf("remove the junction %s to make one of conflux's own in its place: %w", dir, err)
	}

	windows.CloseHandle(r.self)
	r.self = r.dir

	replacing(dir)

	var link windows.Handle

	err = restrictedDir(func(sd *windows.SECURITY_DESCRIPTOR) (err error) {
		link, err = createDir(parent, filepath.Base(dir), sd,
			windows.SYNCHRONIZE|windows.FILE_READ_ATTRIBUTES|windows.FILE_WRITE_ATTRIBUTES|windows.FILE_WRITE_DATA)

		return err
	})

	switch {
	case errors.Is(err, windows.ERROR_ALREADY_EXISTS):
		return fmt.Errorf("%s was made again by somebody else while conflux replaced the junction there, which led "+
			"to %s, so conflux will not use it.\n  %s", dir, leads, remake)
	case err != nil:
		return fmt.Errorf("make a junction of conflux's own at %s: %w\n  %s", dir, err, remake)
	}

	r.self = link

	if err := setMountPoint(link, `\??\`+strings.TrimPrefix(target, `\\?\`), shown); err != nil {
		return fmt.Errorf("point the junction %s at %s: %w\n  %s", dir, leads, err, remake)
	}

	led, err := openFile(dir, windows.FILE_READ_ATTRIBUTES, true)
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}
	defer windows.CloseHandle(led)

	if same, err := sameFile(led, r.dir); err != nil || !same {
		return fmt.Errorf("%s does not lead where it did, %s, once conflux made it a junction of its own (%v), so "+
			"conflux will not use it.\n  %s", dir, leads, err, remake)
	}

	return nil
}

// leadsTo is where dir, a junction or a link, leads, the directory h holds open, named by its
// volume's GUID, as a junction of conflux's can lead to it; one that has no such name, a network
// share's, which a junction cannot lead to, is refused.
func leadsTo(dir string, h windows.Handle) (string, error) {
	target, err := finalPath(h, volumeNameGUID)
	if err != nil {
		return "", fmt.Errorf("read where %s leads, which a junction of conflux's could lead to: %w", dir, err)
	}

	return target, nil
}

// replacing is called once replaceLink has removed the junction it found, before it makes its own
// at the name: nothing, but where a test makes something there meanwhile.
var replacing = func(string) {}

// GetFinalPathNameByHandle's flags: the path by the volume's GUID, or by its drive letter, each
// normalized.
const (
	volumeNameDOS  = 0x0
	volumeNameGUID = 0x1
)

// finalPath is the path of what h holds open, as \\?\ and the volume named as flags says.
func finalPath(h windows.Handle, flags uint32) (string, error) {
	buf := make([]uint16, windows.MAX_PATH)

	for {
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), flags)
		if err != nil {
			return "", err
		}

		if int(n) < len(buf) {
			return windows.UTF16ToString(buf[:n]), nil
		}

		buf = make([]uint16, n)
	}
}

// unlink removes dir, the link self holds open as itself, by its name, once that name is shown to be
// self still: with POSIX semantics where the file system has them, so the name is gone at once,
// though somebody else holds the link open, and otherwise once every handle on it is closed.
func unlink(dir string, self windows.Handle) error {
	h, err := openFile(dir, windows.DELETE|windows.FILE_READ_ATTRIBUTES, false)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)

	if same, err := sameFile(h, self); err != nil || !same {
		return fmt.Errorf("it is not the junction conflux found there (%v)", err)
	}

	posix := uint32(windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_POSIX_SEMANTICS)

	err = windows.SetFileInformationByHandle(h, windows.FileDispositionInfoEx, (*byte)(unsafe.Pointer(&posix)),
		uint32(unsafe.Sizeof(posix)))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_INVALID_FUNCTION) ||
		errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
		del := byte(1) // FILE_DISPOSITION_INFO's DeleteFile

		err = windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &del, 1)
	}

	return err
}

// sameFile reports whether a and b hold one file open: one volume, one file index.
func sameFile(a, b windows.Handle) (bool, error) {
	var fa, fb windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(a, &fa); err != nil {
		return false, err
	}

	if err := windows.GetFileInformationByHandle(b, &fb); err != nil {
		return false, err
	}

	return fa.VolumeSerialNumber == fb.VolumeSerialNumber && fa.FileIndexHigh == fb.FileIndexHigh &&
		fa.FileIndexLow == fb.FileIndexLow, nil
}

// setMountPoint makes the empty directory h holds a junction leading to substitute, an NT path
// (\??\C:\x, \??\Volume{...}\x), shown as display: FSCTL_SET_REPARSE_POINT with REPARSE_DATA_BUFFER's
// MountPointReparseBuffer -- the two names, each counted in bytes without its NUL, in one buffer
// after the lengths. h must have been opened to write its data or its attributes.
func setMountPoint(h windows.Handle, substitute, display string) error {
	sub, shown := utf16.Encode([]rune(substitute)), utf16.Encode([]rune(display))

	b := binary.LittleEndian.AppendUint32(nil, windows.IO_REPARSE_TAG_MOUNT_POINT)
	b = binary.LittleEndian.AppendUint16(b, uint16(8+2*(len(sub)+1)+2*(len(shown)+1)))
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, uint16(2*len(sub)))
	b = binary.LittleEndian.AppendUint16(b, uint16(2*(len(sub)+1)))
	b = binary.LittleEndian.AppendUint16(b, uint16(2*len(shown)))

	for _, c := range append(append(sub, 0), append(shown, 0)...) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}

	var n uint32

	return windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &b[0], uint32(len(b)), nil, 0, &n, nil)
}

// restricted is called once secure has restricted a root through its handle, before it judges what
// the root holds again: nothing, but where a test adds to the root meanwhile.
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
// may point elsewhere, or one leading where no junction of conflux's could (leadsTo), for a DACL
// that lets another account move what is in it, or for anything in it another account may change
// (contents), before anything is made, or nil where dir is this account's or is not there yet. A
// directory another account made, or could have planted something in, is none of conflux's to
// use, and whoever reads one -- an ephemeral run's root, which %ProgramData% lets anybody make
// first -- holds it to this as the conflux that makes one does, through one handle as secure
// does, and reading alone: nothing is run from a root whose contents another account could have
// planted or can point elsewhere.
func Foreign(dir string) error {
	root, err := heldRoot(dir, readAccess)
	if errors.As(err, new(unopened)) {
		return nil
	}

	if err != nil {
		return err
	}
	defer root.close()

	// A link leads where one of conflux's could, as secure holds one: never to a network share.
	if root.link != nil {
		if _, err := leadsTo(dir, root.dir); err != nil {
			return err
		}
	}

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

	if err := moverRefusal(dir, sd,
		"take out what is in it and put something of their own in its place"); err != nil {
		return err
	}

	return contents(dir)
}

// moverRefusal refuses the root dir, whose owner and DACL sd holds as found, where they let an
// account other than those trustedOwner names move it or what is in it (moves), saying what that
// account could then do; or is nil.
func moverRefusal(dir string, sd *windows.SECURITY_DESCRIPTOR, could string) error {
	switch who, _, err := changerIn(dir, sd, moves, "move it or what is in it", nil, false); {
	case err != nil:
		return err
	case who != "":
		return fmt.Errorf("%s %s could %s, so conflux will not use it.\n  Give it a DACL that grants nobody else "+
			"that right, then run this again as Administrator", dir, who, could)
	}

	return nil
}

// readAccess is what a handle that only reads who may change a file is opened for.
const readAccess = windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES

// held is a root held open: itself, as the lookup of its name found it, and the directory it
// is -- the same handle, or for a junction or a link heldLink holds, what it leads to -- and for
// such a link, its own owner and DACL, as heldLink judged them.
type held struct {
	self, dir windows.Handle
	link      *windows.SECURITY_DESCRIPTOR
}

func (r *held) close() {
	if r.dir != r.self {
		windows.CloseHandle(r.dir)
	}

	windows.CloseHandle(r.self)
}

// heldRoot opens dir for access, as itself and never by its name again. A junction or a link is
// held to who may point it elsewhere (heldLink), as a link is on Unix to its owner, and judged
// through the handle that found it; where it is held, what it leads to is opened by following it,
// and that directory, held open, is what is judged after. A handle somebody opened on the link
// while its DACL let them write it may still repoint it between the judgement and that open, so
// where the link led as it was judged answers for nothing; secure replaces it with one of its own
// leading to the directory opened (replaceLink), which nobody may have held open before. Where the
// directory is that is not a plain directory either, it is refused: there is nothing further to
// follow. A root that could not be opened or read, or whose link leads nowhere, is refused as
// unopened.
func heldRoot(dir string, access uint32) (held, error) {
	self, err := openFile(dir, access, false)
	if err != nil {
		return held{}, fmt.Errorf("read %s: %w", dir, unopened{err})
	}

	r := held{self: self, dir: self}

	link, err := isReparse(self)
	if err != nil {
		r.close()

		return held{}, fmt.Errorf("read %s: %w", dir, unopened{err})
	}

	if link {
		sd, err := security(self)
		if err != nil {
			r.close()

			return held{}, fmt.Errorf("read the ownership of %s: %w", dir, err)
		}

		if err := heldLink(dir, sd); err != nil {
			r.close()

			return held{}, err
		}

		r.link = sd

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
// to retargets, as a junction root is. A junction or a link (nameSurrogate) is refused, and not
// followed, whoever may change it: conflux makes none there, and one there could have been opened
// to repoint it while its DACL let somebody. So is anything else another account may write, move
// or point elsewhere -- a directory among them, which an account that may write its data or its
// attributes could make a junction of while it is empty, with a handle that keeps those rights once
// the restriction has replaced what the entry inherited. A reparse point a lookup does not follow,
// as anchord's socket in a SYSTEM anchord's run\anchord\ is, is judged as any other file.
//
// anchord's own account, this installation's service SID (ServiceSID), is conflux's, as the account
// anchord runs as is on Unix: what its DACL grants that SID is discounted, as SYSTEM's and the
// Administrators' grants are. Its owner is not: an entry the SID, or any account but SYSTEM, the
// Administrators, TrustedInstaller and the one running conflux, owns is refused, whatever its name,
// so one another account planted as anchor or run\anchord stays refused. A directory the DACL just
// judged lets that SID write -- anchor\ and run\anchord\, as MakeAnchordDir makes them -- is not
// gone into: its DACL, which has just shown nobody else may write it, lets only SYSTEM, the
// Administrators and anchord make anything inside, and what anchord makes there, which it owns,
// conflux reads as anchord's, untrusted (OpenUntrusted, config.ReadUntrusted, copyTree).
//
// An entry gone between the listing and its judgement is passed over: nothing is there to judge, and
// a live run's root -- an ephemeral one, which Foreign reads -- has its marker written and removed
// while it runs.
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
			var h windows.Handle
			if err == nil {
				if h, err = openFile(p, readAccess, false); err != nil {
					err = fmt.Errorf("read %s: %w", p, err)
				}
			}

			switch {
			case errors.Is(err, fs.ErrNotExist):
				return nil // gone since it was listed, as what a live run writes and removes may be
			case err != nil:
				return err
			}
			defer windows.CloseHandle(h)

			switch link, err := nameSurrogate(h); {
			case err != nil:
				return fmt.Errorf("read %s: %w", p, err)
			case link:
				return fmt.Errorf("%s, a junction or a link, is in %s, where conflux makes none, so conflux will not "+
					"use it.\n  Remove it, then run this again as Administrator", p, dir)
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

// heldLink refuses dir, a junction or a link whose own owner and DACL sd holds, where an account
// other than those trustedOwner names may point it elsewhere: by owning it, or by a grant of
// retargets in its DACL. Owners and DACLs read by name follow a junction, so the directory it leads
// to would otherwise answer for it, and %ProgramData% lets any user make one where
// %ProgramData%\conflux or conflux-ephemeral is not yet, leading into a directory of SYSTEM's,
// and point it at one of their own once conflux has filled it, with a conflux.exe for the
// service to run as SYSTEM. Held as a link is on Unix, by its owner, and here by its DACL too.
func heldLink(dir string, sd *windows.SECURITY_DESCRIPTOR) error {
	who, _, err := changerIn(dir, sd, retargets, "point it elsewhere or move it", nil, false)
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

// nameSurrogate reports whether h is a reparse point a lookup follows -- a junction, a mount point
// or a symbolic link, whose tag says it stands for another name (IsReparseTagNameSurrogate) --
// rather than one holding something of its own, as anchord's AF_UNIX socket does.
func nameSurrogate(h windows.Handle) (bool, error) {
	var info struct{ FileAttributes, ReparseTag uint32 } // FILE_ATTRIBUTE_TAG_INFO
	if err := windows.GetFileInformationByHandleEx(h, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info))); err != nil {
		return false, err
	}

	return info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 && info.ReparseTag&reparseTagNameSurrogate != 0, nil
}

// reparseTagNameSurrogate is the bit of a reparse tag that says it stands for another name.
const reparseTagNameSurrogate = 0x20000000

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

// moves is what an ACE on a directory above a root, or on a root's own DACL as secure and Foreign
// find it, must not grant another account: to delete or rename what is in it, to delete or rename
// the directory itself, or to change who may. Above a root, whoever may could move it aside and put
// another in its place; on the root, a handle opened under such a grant keeps it once the root is
// restricted, and could take out what fill puts there. Creating folders in it is not among them:
// C:\ lets every user do that, and a folder of theirs cannot take the place of one that is not, as
// a sticky directory's cannot on Unix.
const moves = fileDeleteChild | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL

// retargets is what an ACE on a link or a junction, or on anything in a root, must not grant
// another account: moves, or a right that writes it -- its data, or on a folder a file or a folder
// added to it, its attributes or its extended attributes -- among them what rewrites where it leads,
// since setting a reparse point takes FILE_WRITE_DATA or FILE_WRITE_ATTRIBUTES (MS-FSA
// 2.1.5.10.37); or GENERIC_WRITE, which holds them all.
const retargets = moves | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_ATTRIBUTES |
	windows.FILE_WRITE_EA | windows.GENERIC_WRITE

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

// changer is changerIn of p, held open as itself by h, over the owner and DACL read through h, and
// what they allow on p itself.
func changer(p string, h windows.Handle, rights windows.ACCESS_MASK, what string,
	anchord *windows.SID) (who string, anchords bool, err error) {
	sd, err := security(h)
	if err != nil {
		return "", false, fmt.Errorf("read the ownership of %s: %w", p, err)
	}

	return changerIn(p, sd, rights, what, anchord, false)
}

// changerIn is who besides SYSTEM, the Administrators, TrustedInstaller and the account running
// conflux may change p, whose owner and DACL sd holds, as a refusal names them, or "": its owner,
// who may grant itself anything, or anybody but anchord, where it is given, its DACL grants one of
// rights -- on p itself, or, where passedOn, on what is made in it too (mover) -- which lets them
// what. anchords is whether the DACL grants anchord one of them.
func changerIn(p string, sd *windows.SECURITY_DESCRIPTOR, rights windows.ACCESS_MASK, what string,
	anchord *windows.SID, passedOn bool) (who string, anchords bool, err error) {
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

	sid, anchords, err := mover(dacl, rights, anchord, passedOn)
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

// mover is the first account dacl grants one of rights on the object itself, or, where passedOn,
// on what is made in it too, other than those trustedOwner names and anchord, where it is given, or
// nil; and whether it grants anchord one of them before it: each entry that allows rights there, as
// windowsGrants reads them.
func mover(dacl *windows.ACL, rights windows.ACCESS_MASK, anchord *windows.SID,
	passedOn bool) (*windows.SID, bool, error) {
	header := unsafe.Slice((*byte)(unsafe.Pointer(dacl)), 8)

	grants, err := windowsGrants(unsafe.Slice((*byte)(unsafe.Pointer(dacl)), binary.LittleEndian.Uint16(header[2:])),
		passedOn)
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
