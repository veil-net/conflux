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
	"syscall"
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

// aLink is what makeWay calls a link made where it was making a folder.
const aLink = "a junction or a link"

// step is a folder, or a junction or a link, a walk holds open as itself.
type step struct{ h windows.Handle }

func (s step) close() { windows.CloseHandle(s.h) }

// openTop holds the top of the volume vol open -- a drive (C:), a volume by its GUID, or a share
// (\\host\share) -- to read who may change it, and refuses it where it is on a network volume
// (remote): who owns what is there, and whom its DACLs grant, are accounts of the machine serving
// it, which this one cannot judge, so nothing is judged, looked up or made there.
func openTop(vol string) (step, error) {
	top := vol + `\`

	h, err := openFile(top, readAccess, false)
	if err != nil {
		return step{}, fmt.Errorf("read %s: %w", top, err)
	}

	if err := remote(top, h); err != nil {
		windows.CloseHandle(h)

		return step{}, err
	}

	return step{h}, nil
}

// lookUp is what is at name in the folder parent holds open, held open as itself to read who may
// change it, and whether it is a junction or a link (a name surrogate, as nameSurrogate reads one):
// looked up there and nowhere else, never followed, nor reparsed anywhere (ntOpen). Anything else
// that is not a folder is refused, and nothing at the name is an error that is fs.ErrNotExist.
func lookUp(parent step, name string) (step, bool, error) {
	h, err := ntOpen(parent.h, name, nil, windows.SYNCHRONIZE|readAccess, windows.FILE_OPEN, 0)
	if err != nil {
		return step{}, false, err
	}

	attributes, tag, err := attributeTag(h)

	switch {
	case err != nil:
	case attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 && tag&reparseTagNameSurrogate != 0:
		return step{h}, true, nil
	case attributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0:
		err = syscall.ENOTDIR
	default:
		return step{h}, false, nil
	}

	windows.CloseHandle(h)

	return step{}, false, err
}

// readLink is where the junction or link s holds open leads, read off it (linkTarget): one that may
// lead off this machine is refused unfollowed.
func readLink(s step) (string, error) { return linkTarget(s.h) }

// makeStep makes the folder name in the one parent holds open, and holds it open: through parent
// (createDir), looked up there and nowhere else and never followed, the root with Restrict's
// ownership and DACL set as it is created (createIn), and a folder on the way with nothing set but
// what the one before passes on. ERROR_ALREADY_EXISTS is anything already at the name, a link
// included.
func makeStep(parent step, name string, root bool) (step, bool, error) {
	const access = windows.SYNCHRONIZE | windows.FILE_READ_ATTRIBUTES

	var (
		h   windows.Handle
		err error
	)

	if root {
		h, err = createIn(parent.h, name, access)
	} else {
		h, err = createDir(parent.h, name, nil, access)
	}

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

// fill makes the root dir, held open by h, hold something -- its run directory, which EnsureAll
// makes there anyway, with Restrict's ownership and DACL set as it is created, made through h: its
// name looked up in the directory h holds and nowhere else -- and reads h again: one that became a
// junction or a link before then is refused. A reparse point cannot be set on a directory that is
// not empty (FSCTL_SET_REPARSE_POINT fails with STATUS_DIRECTORY_NOT_EMPTY), so a handle somebody
// opened on the root while its DACL let them write it, which keeps the rights it was opened with,
// can no longer make a junction of it, and the run directory, SYSTEM's and the Administrators', is
// not theirs to remove. Anything already there by that name does the same, and is judged with the
// rest of what the root holds (contents). A root whose DACL does not let this account create a
// folder in it is refused, saying so: it is filled before what the root holds is judged or the
// root restricted, under the DACL secure found.
func fill(dir string, h windows.Handle) error {
	filling(dir)

	run, filled := createIn(h, runName, windows.SYNCHRONIZE|windows.FILE_READ_ATTRIBUTES)
	if filled == nil {
		filled = windows.CloseHandle(run)
	}

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

// createIn creates the directory name in the one parent holds open, with Restrict's ownership and
// DACL set as it is created (restrictedDir), through parent (createDir), and holds it open for
// access: ERROR_ALREADY_EXISTS where anything is at the name, a link included, which is not
// followed.
func createIn(parent windows.Handle, name string, access uint32) (windows.Handle, error) {
	var h windows.Handle

	err := restrictedDir(func(sd *windows.SECURITY_DESCRIPTOR) (err error) {
		h, err = createDir(parent, name, sd, access)

		return err
	})

	return h, err
}

// filling is called before secure fills a root: nothing, but where a test turns the root into a
// junction meanwhile.
var filling = func(string) {}

// createDir creates the directory name in the one parent holds open, with sd as its security
// descriptor, and holds it open for access: its name looked up there and nowhere else, and never
// followed (FILE_OPEN_REPARSE_POINT). The create is also kept from being reparsed anywhere
// (OBJ_DONT_REPARSE), so that a parent that became a junction or a mount point after it was opened
// would fail it rather than take it to where it leads: defence in depth, guarding a case not shown
// to happen, since a create relative to a held directory is not known to be reparsed through it
// without the flag either. A status NtCreateFile fails with is returned as the Win32 error it maps
// to, as CreateDirectory returns one -- ERROR_ALREADY_EXISTS for a name already taken -- so that
// restrictWith tells a refused owner.
func createDir(parent windows.Handle, name string, sd *windows.SECURITY_DESCRIPTOR, access uint32) (windows.Handle, error) {
	return ntOpen(parent, name, sd, access, windows.FILE_CREATE, windows.FILE_DIRECTORY_FILE)
}

// ntOpen is createDir and lookUp's open: NtCreateFile of name relative to parent, as disposition
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
	if chosen(dir) {
		if err := parents(dir); err != nil {
			return err
		}
	}

	root, err := heldRoot(dir, rootAccess)
	if err != nil {
		return err
	}
	defer root.close()

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
	switch who, _, err := changerIn(dir, sd, moves, "move it or what is in it", nil, false); {
	case err != nil:
		return err
	case who != "":
		return fmt.Errorf("%s %s could take out what conflux puts in it, with a handle opened now that keeps the "+
			"right once conflux restricts it, so conflux will not use it.\n  Give it a DACL that grants nobody "+
			"else that right, then run this again as Administrator", dir, who)
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
// hold it open, and another made at its name through a handle of conflux's, created with Restrict's
// ownership and DACL -- so nobody else can ever have opened it to write -- and given r.dir as its
// reparse point through that handle. A handle somebody opened on the one found, which keeps the
// rights it was opened with, can repoint nothing anybody reaches by the name. Something made at the
// name before conflux makes its own is refused, naming where the junction led and saying how to
// make it again first: with nothing at the name, the next run would make a root afresh there, and
// the machine a new identity. It leads to r.target, the directory's name by its volume's GUID,
// which heldRoot read (leadsTo). A failure to make or point its own says the same as something made
// at the name; a kill in that instant says nothing, and leaves nothing, or conflux's empty
// directory, at the name, which windows.md tells an operator to remove and make the junction again
// in place of. r.self is the new junction after.
func replaceLink(dir string, r *held) error {
	target := r.target

	shown, _ := finalPath(r.dir, volumeNameDOS) // what dir shows it leads to; nothing where it has no such name
	shown = strings.TrimPrefix(shown, `\\?\`)

	// Where the junction led, as a refusal names it to make it again: by its drive letter where it has
	// one.
	leads := shown
	if leads == "" {
		leads = target
	}

	remake := remakeJunction(dir, leads)

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

	link, err := createIn(parent, filepath.Base(dir),
		windows.SYNCHRONIZE|windows.FILE_READ_ATTRIBUTES|windows.FILE_WRITE_ATTRIBUTES|windows.FILE_WRITE_DATA)

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

// remakeJunction is the way on from a refusal once the junction at dir, which led to leads, is gone:
// the junction made again, before conflux runs again. Made at the name, a junction carries what the
// folder it is in passes on -- in %ProgramData%, Users' right to write its attributes, enough to
// point it elsewhere -- which the next run refuses (heldLink). So it is made in a folder only
// SYSTEM, the Administrators and TrustedInstaller may write, on dir's volume, and moved into place,
// which on one volume keeps the DACL it was made with: unprotected, so the next run replaces it with
// conflux's own. The commands that do it, in cmd, where mklink is, and whose rmdir removes a junction
// without going into where it leads, make it in %ProgramFiles%, and are given only where that is on
// dir's volume, since move cannot take a junction from one volume to another; elsewhere the folder
// is the operator's to choose, and the refusal says so, naming the volume.
func remakeJunction(dir, leads string) string {
	remake := "Remove whatever is at its name, and make the junction again before conflux runs, or it would make " +
		"a new root there, and the machine a new identity. Made at its name, the junction would carry what the " +
		"folder it is in passes on, in %ProgramData% Users' right to write its attributes, and be refused; so " +
		"make it in a folder only SYSTEM and the Administrators may write, on the same volume, and move it into " +
		"place."

	if vol := filepath.VolumeName(dir); !strings.EqualFold(filepath.VolumeName(os.Getenv("ProgramFiles")), vol) {
		return remake + " %ProgramFiles% is not on " + vol + ", so choose such a folder there; then, in cmd, not " +
			`PowerShell, as Administrator, remove "` + dir + `" with rmdir, make the junction to "` + leads +
			`" in that folder with mklink /J, move it to "` + dir + `", and run this again`
	}

	stage := `%ProgramFiles%\` + filepath.Base(dir) + ".junction"

	return remake + " In cmd, not PowerShell, as Administrator:\n" +
		`    rmdir "` + dir + `"` + "\n" +
		`    mklink /J "` + stage + `" "` + leads + `"` + "\n" +
		`    move "` + stage + `" "` + dir + `"` + "\n" +
		"  then run this again"
}

// leadsTo is where dir, a junction or a link, leads, the directory h holds open, named by its
// volume's GUID, as a junction of conflux's can lead to it; one that has no such name, which a
// junction cannot lead to -- a network share's, which heldRoot refuses first (remote), or a local
// volume's the mount manager does not name -- is refused, and not as a directory that is not there:
// GetFinalPathNameByHandle says ERROR_PATH_NOT_FOUND of it.
func leadsTo(dir string, h windows.Handle) (string, error) {
	target, err := finalPath(h, volumeNameGUID)
	if err != nil {
		return "", fmt.Errorf("read where %s leads, which a junction of conflux's could lead to: %v", dir, err)
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
// (\??\C:\x, \??\Volume{...}\x), shown as display: FSCTL_SET_REPARSE_POINT with mountPointData. h
// must have been opened to write its data or its attributes.
func setMountPoint(h windows.Handle, substitute, display string) error {
	b := mountPointData(substitute, display)

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

// checkRoot is Check's judgement of the root dir, here: held open, as itself where it is a junction
// or a link, and to read alone (heldRoot), so that a link leading off this machine or nowhere, one
// another account may point elsewhere, and a root on a network volume are refused; then refused
// where its owner is not SYSTEM, the Administrators or the account running conflux (ownerRefusal),
// or where its DACL lets another account write it, add to it, move it, point it elsewhere or change
// who may, on itself or on what is made in it -- the rule secure keeps a root it finds secured
// already to. A CONFLUX_DIR is held to its parents first (parents), which also refuses a link on
// the way to it that leads off this machine before anything is looked up through it. A root this
// account may not open or read is refused, since whoever made it can deny conflux the right to read
// its owner and DACL as easily as they can make it.
func checkRoot(dir string) error {
	if chosen(dir) {
		if err := parents(dir); err != nil {
			return err
		}
	}

	root, err := heldRoot(dir, readAccess)
	if err != nil {
		return err
	}
	defer root.close()

	sd, err := security(root.dir)
	if err != nil {
		return fmt.Errorf("read the ownership of %s: %w", dir, err)
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read the owner of %s: %w", dir, err)
	}

	if err := ownerRefusal(dir, owner); err != nil {
		return err
	}

	switch who, _, err := changerIn(dir, sd, retargets, "write it or what is made in it", nil, true); {
	case err != nil:
		return err
	case who != "":
		return fmt.Errorf("%s %s could put what they like in it for conflux to read or run, so conflux will not "+
			"use it.\n  Give it a DACL that grants nobody else that right, then run this again as Administrator",
			dir, who)
	}

	return nil
}

// readAccess is what a handle that only reads who may change a file is opened for.
const readAccess = windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES

// held is a root held open: itself, as the lookup of its name found it, and the directory it
// is -- the same handle, or for a junction or a link heldLink holds, what it leads to -- and for
// such a link, its own owner and DACL, as heldLink judged them, and where it leads, by the
// directory's volume's GUID (leadsTo), as replaceLink points a junction of conflux's there.
type held struct {
	self, dir windows.Handle
	link      *windows.SECURITY_DESCRIPTOR
	target    string
}

func (r *held) close() {
	if r.dir != r.self {
		windows.CloseHandle(r.dir)
	}

	windows.CloseHandle(r.self)
}

// heldRoot opens dir for access, as itself and never by its name again. A junction or a link is
// read for where it leads first, off the link and not by following it, and refused where that may
// be another machine (linkTarget), so that following it never signs this one in there; then it is
// held to who may point it elsewhere (heldLink), as a link is on Unix to its owner, and judged
// through the handle that found it; where it is held, what it leads to is opened by following it,
// and that directory, held open, is what is judged after. A handle somebody opened on the link
// while its DACL let them write it may still repoint it between the judgement and that open, so
// where the link led as it was judged answers for nothing; secure replaces it with one of its own
// leading to the directory opened (replaceLink), which nobody may have held open before, unless it
// finds it secured already (security.md's first gap, a kept handle). Where the directory is that is
// not a plain directory either, it is refused: there is nothing further to follow; so is one on a
// network volume (remote), and, for a link, one its volume's GUID does not name, where no junction
// of conflux's could lead (leadsTo). A root that could not be opened or read is refused, saying
// why, as is a link that leads nowhere, which is refused as one conflux cannot follow, never as a
// root that is not there.
func heldRoot(dir string, access uint32) (held, error) {
	self, err := openFile(dir, access, false)
	if err != nil {
		return held{}, fmt.Errorf("read %s: %w", dir, err)
	}

	r := held{self: self, dir: self}

	link, err := isReparse(self)
	if err != nil {
		r.close()

		return held{}, fmt.Errorf("read %s: %w", dir, err)
	}

	if link {
		if _, err := linkTarget(self); err != nil && !errors.Is(err, errNotLink) {
			r.close()

			return held{}, fmt.Errorf("%s is a link conflux will not follow, so conflux will not use it: %v.\n"+
				"  Point it at a folder on a volume of this machine's own, then run this again as Administrator", dir, err)
		}

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

		led, err := openFile(dir, access, true)
		if err != nil {
			r.close()

			return held{}, fmt.Errorf("%s is a link conflux cannot follow (%v), so conflux will not use it.\n"+
				"  Remove it, then run this again as Administrator", dir, err)
		}

		r.dir = led

		if err := notLink(dir, r.dir, "leads to a reparse point conflux cannot follow"); err != nil {
			r.close()

			return held{}, err
		}
	}

	if err := remote(dir, r.dir); err != nil {
		r.close()

		return held{}, err
	}

	if r.link != nil {
		if r.target, err = leadsTo(dir, r.dir); err != nil {
			r.close()

			return held{}, err
		}
	}

	return r, nil
}

// remote refuses dir, whose directory h holds open, where that is on a network volume -- a share
// reached by its UNC path, a drive mapped to one, or a link leading to either -- as the device the
// volume is on says of itself (FILE_FS_DEVICE_INFORMATION, which GetDriveType reads DRIVE_REMOTE
// from), and not as dir is spelled. Who owns what is there, and whom its DACL grants, are the
// accounts of the machine serving it -- its Administrators are not this machine's -- which this one
// cannot judge, as no junction of conflux's could lead there either (leadsTo).
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
// judged by its own owner and DACL, read without following it, as parentsRule reads them, and held to
// retargets, as a junction root is. A junction or a link (nameSurrogate) is refused, and not
// followed, whoever may change it: conflux makes none there, and one there could have been opened
// to repoint it while its DACL let somebody. So is anything else another account may write, move or
// point elsewhere -- a directory among them, which an account that may write its data or its
// attributes could make a junction of while it is empty, with a handle that keeps those rights once
// the restriction has replaced what the entry inherited -- and a directory whose DACL passes such a
// right on to what is made in it, as an inherit-only grant on logs\ would to conflux.log, which the
// service writes there. A reparse point a lookup does not follow, as anchord's socket in a SYSTEM
// anchord's run\anchord\ is, is judged as any other file.
//
// anchord's own account, this installation's service SID (ServiceSID), is conflux's, as the account
// anchord runs as is on Unix: what its DACL grants that SID is discounted, as SYSTEM's and the
// Administrators' grants are, what it passes on to what is made in a directory among them --
// MakeAnchordDir's grant to anchord of what anchor\ and run\anchord\ hold. Its owner is not: an
// entry the SID, or any account but SYSTEM, the Administrators, TrustedInstaller and the one
// running conflux, owns is refused, whatever its name, so one another account planted as anchor or
// run\anchord stays refused. A directory the DACL just judged lets that SID write -- anchor\ and
// run\anchord\, as MakeAnchordDir makes them -- is not gone into: its DACL, which has just shown
// nobody else may write it, lets only SYSTEM, the Administrators and anchord make anything inside,
// and what anchord makes there, which it owns, conflux reads as anchord's, untrusted
// (OpenUntrusted, config.ReadUntrusted, copyTree).
//
// An entry gone between the listing and its judgement is passed over: nothing is there to judge,
// and a live run's root -- an ephemeral one, which Foreign reads -- has its marker written and
// removed while it runs.
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

			what := "write it, move it or make a junction of it"
			if d.IsDir() {
				what = "write it or what is made in it, move it or make a junction of it"
			}

			who, anchords, err := changer(p, h, retargets, what, anchord, d.IsDir())
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
	attributes, tag, err := attributeTag(h)

	return attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 && tag&reparseTagNameSurrogate != 0, err
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

// moves is what an ACE on a directory above a root, or on a root's own DACL as secure finds it,
// must not grant another account: to delete or rename what is in it, to delete or rename
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

// parentsRule is parents' rule for dir: a folder on the way to it is refused where an account other
// than SYSTEM, Administrators, TrustedInstaller and the one running conflux owns it, which lets it
// grant itself anything, or is granted one of moves on it -- whoever may move a parent can put a
// directory of their own where dir is, with a conflux in it for the service to run as SYSTEM -- and
// a link or a junction is held to the same, as itself, and to retargets, since whoever may point it
// elsewhere may as well. Each is judged by the owner and DACL read through the handle the walk holds
// it by.
func parentsRule(dir string) judgement {
	return func(p string, s step, link bool) error {
		where, what, rights := "inside", "move it or what is in it", windows.ACCESS_MASK(moves)
		if link {
			where, what, rights = "reached through", "point it elsewhere or move it", retargets
		}

		who, _, err := changer(p, s.h, rights, what, nil, false)
		if err == nil && who != "" {
			err = fmt.Errorf("%s is %s %s, which %s could move it aside and put another in its place for conflux "+
				"to run.\n  Choose a CONFLUX_DIR whose every parent only SYSTEM, the Administrators and this account "+
				"can change", dir, where, p, who)
		}

		return err
	}
}

// parents refuses dir where its way, walked from the top of its volume (walk), is not there, or is
// not held to parents' rule (parentsRule).
func parents(dir string) error { return judgeWay(dir, parentsRule(dir)) }

// changer is changerIn of p, held open as itself by h, over the owner and DACL read through h, and
// what they allow on p itself, or, where passedOn, on what is made in it too.
func changer(p string, h windows.Handle, rights windows.ACCESS_MASK, what string,
	anchord *windows.SID, passedOn bool) (who string, anchords bool, err error) {
	sd, err := security(h)
	if err != nil {
		return "", false, fmt.Errorf("read the ownership of %s: %w", p, err)
	}

	return changerIn(p, sd, rights, what, anchord, passedOn)
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
