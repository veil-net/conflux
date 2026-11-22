package privtest

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WithRestore runs f with SeRestorePrivilege enabled in this process's token, as an
// Administrator's holds it, and disabled again after, and is what f returns: naming an owner the
// token does not carry, SYSTEM's or another account's, takes it.
func WithRestore(tb testing.TB, f func() error) error {
	tb.Helper()

	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
		&tok); err != nil {
		tb.Fatal(err)
	}
	defer tok.Close()

	luid := LUID(tb, "SeRestorePrivilege")

	set := func(attributes uint32) {
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: attributes}

		if err := windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil); err != nil {
			tb.Fatal(err)
		}
	}

	set(windows.SE_PRIVILEGE_ENABLED)
	defer set(0)

	return f()
}

// LUID is the locally unique id this machine knows the privilege name by.
func LUID(tb testing.TB, name string) windows.LUID {
	tb.Helper()

	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		tb.Fatal(err)
	}

	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, n, &luid); err != nil {
		tb.Fatal(err)
	}

	return luid
}

// Users is BUILTIN\Users, every account on the machine; System is NT AUTHORITY\SYSTEM, and Admins
// BUILTIN\Administrators.
var (
	Users  = wellKnown(windows.WinBuiltinUsersSid)
	System = wellKnown(windows.WinLocalSystemSid)
	Admins = wellKnown(windows.WinBuiltinAdministratorsSid)
)

func wellKnown(kind windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	sid, err := windows.CreateWellKnownSid(kind)
	if err != nil {
		panic("privtest: " + err.Error())
	}

	return sid
}

// GrantUsers gives Users access to path, beside what its DACL grants already, passed on to what
// path holds as inherit says: its DACL read and written by name, so through a link or a junction
// it is the DACL of where it leads.
func GrantUsers(tb testing.TB, path string, access windows.ACCESS_MASK, inherit uint32) {
	tb.Helper()

	addEntry(tb, path, usersGranted(access, inherit))
}

// Grant gives the account sid access to path, as GrantUsers gives Users: the folder of an
// administrator's profile, which grants that account full control, among what it stands for.
func Grant(tb testing.TB, path string, sid *windows.SID, access windows.ACCESS_MASK, inherit uint32) {
	tb.Helper()

	e := usersGranted(access, inherit)
	e.Trustee.TrusteeType, e.Trustee.TrusteeValue = windows.TRUSTEE_IS_USER, windows.TrusteeValueFromSID(sid)

	addEntry(tb, path, e)
}

// ServiceTemp points this process's temporary directory -- TMP and TEMP, which os.TempDir, and so
// a test's TempDir, read -- at conflux-tests on the system's volume, the one its Windows directory is
// on, read from the system and never from SystemDrive, which a test may change: a folder only SYSTEM and
// the Administrators may change, the Administrators', named so, under a protected DACL granting the two
// of them full control and nobody else anything, as conflux makes a root, made so where it is not
// there yet and given so again where it is: what a test makes there -- an installation's root among it,
// which pathstest keeps there -- is in a folder of the system's, as the installation's root is, rather
// than in %TEMP%, deep in the profile of the administrator running the tests, which grants that account
// full control and passes it on to what is made there, so that a folder a test makes and judges carries
// only what the test gives it. Its callers make the
// Administrators the owner of what the process makes first (paths.ElevatedDefaultOwner), as every
// conflux process does as it starts; privtest itself imports nothing of conflux's. A variable already naming a
// folder beneath conflux-tests is left as it is: a child of a test binary keeps the temporary
// directory its test gave it.
func ServiceTemp() error {
	sys, err := windows.GetSystemWindowsDirectory()

	drive := filepath.VolumeName(sys)
	if err != nil || drive == "" {
		drive = "C:"
	}

	dir := drive + `\conflux-tests`

	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}

	const protected = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

	for _, sddl := range []string{"O:BA" + protected, protected} {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			return err
		}

		err = windows.CreateDirectory(name, &windows.SecurityAttributes{
			Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
			SecurityDescriptor: sd,
		})
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			err = giveAgain(dir, sd)
		}

		if errors.Is(err, windows.ERROR_INVALID_OWNER) {
			continue // a token that may not name the Administrators its owner: its own, then
		}

		if err != nil {
			return fmt.Errorf("make %s: %w", dir, err)
		}

		break
	}

	for _, v := range []string{"TMP", "TEMP"} {
		if was := os.Getenv(v); len(was) > len(dir) && strings.EqualFold(was[:len(dir)+1], dir+`\`) {
			continue
		}

		if err := os.Setenv(v, dir); err != nil {
			return err
		}
	}

	return nil
}

// giveAgain gives dir, there already, the owner, where sd names one, and the protected DACL sd holds:
// a run before may have left it another owner, under another policy or another ServiceTemp. Read
// first, and written only where it differs: every test binary calls this as it starts, and go test
// runs them side by side, and a DACL written by name is passed on to every folder below that does not
// protect its own -- the TempDirs other binaries are using among them, which some give a DACL of
// their own while this one rewrites theirs.
func giveAgain(dir string, sd *windows.SECURITY_DESCRIPTOR) error {
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}

	was, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}

	if same, err := holds(was, owner, dacl); err != nil || same {
		return err
	}

	return setSecurity(dir, sd)
}

// SetSecurity gives path the owner, where sddl names one, and the protected DACL -- or the NULL one,
// NO_ACCESS_CONTROL -- that sddl holds, by name.
func SetSecurity(tb testing.TB, path, sddl string) {
	tb.Helper()

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		tb.Fatal(err)
	}

	if err := setSecurity(path, sd); err != nil {
		tb.Fatalf("give %s %s: %v", path, sddl, err)
	}
}

// setSecurity gives path the owner, where sd names one, and the DACL sd holds, protected, by name.
func setSecurity(path string, sd *windows.SECURITY_DESCRIPTOR) error {
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}

	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if owner != nil {
		info |= windows.OWNER_SECURITY_INFORMATION
	}

	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil)
}

// holds reports whether sd is owned by owner, where owner is given, and holds dacl, protected: the
// same entries, in the same order.
func holds(sd *windows.SECURITY_DESCRIPTOR, owner *windows.SID, dacl *windows.ACL) (bool, error) {
	if owner != nil {
		has, _, err := sd.Owner()
		if err != nil || !has.Equals(owner) {
			return false, err
		}
	}

	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false, err
	}

	has, _, err := sd.DACL()
	if err != nil || has == nil || dacl == nil || has.AceCount != dacl.AceCount {
		return false, err
	}

	for i := range uint32(dacl.AceCount) {
		var a, b *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(has, i, &a); err != nil {
			return false, err
		}

		if err := windows.GetAce(dacl, i, &b); err != nil {
			return false, err
		}

		size := a.Header.AceSize
		if size != b.Header.AceSize || !bytes.Equal(unsafe.Slice((*byte)(unsafe.Pointer(a)), size),
			unsafe.Slice((*byte)(unsafe.Pointer(b)), size)) {
			return false, nil
		}
	}

	return true, nil
}

// CreatorOwns makes what this process makes without naming an owner its user's own -- the account
// its token is for -- as a Windows client's default-owner policy makes it for an elevated
// administrator, where Windows Server's makes it the Administrators', until restore, which tb's
// cleanup runs too, gives back the owner the token gave before: the Administrators, where the test
// binary made them so as conflux does as it starts (paths.ElevatedDefaultOwner). What an
// administrator makes on a Windows client without conflux, or what an older conflux made there, in
// a test on Server. Not for a parallel test: the owner is the whole process's.
func CreatorOwns(tb testing.TB) (restore func()) {
	tb.Helper()

	was, err := defaultOwner()
	if err != nil {
		tb.Fatal(err)
	}

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		tb.Fatal(err)
	}

	if err := setDefaultOwner(user.User.Sid); err != nil {
		tb.Fatalf("make this account the owner of what this process makes: %v", err)
	}

	var once sync.Once

	restore = func() {
		once.Do(func() {
			if err := setDefaultOwner(was); err != nil {
				tb.Errorf("give back the owner of what this process makes, %v: %v", was, err)
			}
		})
	}

	tb.Cleanup(restore)

	return restore
}

// tokenOwner is TOKEN_OWNER: the owner a token gives what it makes without naming one.
type tokenOwner struct{ owner *windows.SID }

// defaultOwner is the owner this process's token gives what it makes without naming one.
func defaultOwner() (*windows.SID, error) {
	tok := windows.GetCurrentProcessToken()

	var n uint32
	_ = windows.GetTokenInformation(tok, windows.TokenOwner, nil, 0, &n)

	if n < uint32(unsafe.Sizeof(tokenOwner{})) {
		return nil, errors.New("read the owner this process's token gives: no answer")
	}

	b := make([]byte, n)
	if err := windows.GetTokenInformation(tok, windows.TokenOwner, &b[0], n, &n); err != nil {
		return nil, fmt.Errorf("read the owner this process's token gives: %w", err)
	}

	return (*tokenOwner)(unsafe.Pointer(&b[0])).owner.Copy()
}

// setDefaultOwner makes owner -- the token's user, or a group it holds that may own -- the owner this
// process's token gives what it makes without naming one. paths.ElevatedDefaultOwner writes the
// same for the Administrators, but privtest imports nothing of conflux's -- paths' own tests import
// it, and an import of paths would be a cycle -- so CreatorOwns, which names the user, has this.
func setDefaultOwner(owner *windows.SID) error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_QUERY,
		&tok); err != nil {
		return err
	}
	defer tok.Close()

	info := tokenOwner{owner}

	return windows.SetTokenInformation(tok, windows.TokenOwner, (*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)))
}

// SetOwner makes sid the owner of path, by name, and leaves its DACL as it is.
func SetOwner(tb testing.TB, path string, sid *windows.SID) {
	tb.Helper()

	if err := WithRestore(tb, func() error {
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, sid,
			nil, nil, nil)
	}); err != nil {
		tb.Fatalf("make %v the owner of %s: %v", sid, path, err)
	}
}

// ProgramDataGrant gives Users, on dir and every folder made in it, what %ProgramData% gives them:
// the right to add a file or a folder (on a folder, writing its data or appending to it), and to
// write its extended attributes and attributes.
func ProgramDataGrant(tb testing.TB, dir string) {
	tb.Helper()

	GrantUsers(tb, dir, windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA|windows.FILE_WRITE_EA|
		windows.FILE_WRITE_ATTRIBUTES, windows.SUB_CONTAINERS_ONLY_INHERIT)
}

// WithUsers is dacl with access granted to Users on the object itself, and passed on as inherit
// says, merged in as SetEntriesInAcl merges an entry.
func WithUsers(tb testing.TB, dacl *windows.ACL, access windows.ACCESS_MASK, inherit uint32) *windows.ACL {
	tb.Helper()

	return withEntry(tb, dacl, usersGranted(access, inherit))
}

// usersGranted is an entry granting Users access, passed on as inherit says.
func usersGranted(access windows.ACCESS_MASK, inherit uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: access,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inherit,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(Users),
		},
	}
}

// DenyOwnersTheirDACL passes on to everything made in dir, and gives dir itself, an entry denying
// whoever owns it the right to change its DACL -- (D;OICI;WD;;;OW), OWNER RIGHTS -- beside what
// its DACL holds: a directory made in dir and given its DACL afterwards is refused that, by the
// entry it inherited, while one made with its own protected descriptor never carries it.
func DenyOwnersTheirDACL(tb testing.TB, dir string) {
	tb.Helper()

	ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	if err != nil {
		tb.Fatal(err)
	}

	addEntry(tb, dir, windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.WRITE_DAC,
		AccessMode:        windows.DENY_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(ownerRights),
		},
	})
}

// addEntry merges e into path's DACL, read and written by name.
func addEntry(tb testing.TB, path string, e windows.EXPLICIT_ACCESS) {
	tb.Helper()

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		tb.Fatal(err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		tb.Fatal(err)
	}

	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
		nil, nil, withEntry(tb, dacl, e), nil); err != nil {
		tb.Fatal(err)
	}
}

// withEntry is dacl with e merged in, as SetEntriesInAcl merges an entry.
func withEntry(tb testing.TB, dacl *windows.ACL, e windows.EXPLICIT_ACCESS) *windows.ACL {
	tb.Helper()

	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{e}, dacl)
	if err != nil {
		tb.Fatal(err)
	}

	return acl
}

// Security is what a file's security descriptor says of who holds it.
type Security struct {
	Owner *windows.SID

	// Protected is SE_DACL_PROTECTED: the DACL is the file's own, with nothing its directory
	// passes on merged in.
	Protected bool

	// Entries are the DACL's, in its order.
	Entries []Entry
}

// Entry is one ACE: its type, its flags (how it is passed on), the rights it names, and the SID it
// names them for.
type Entry struct {
	Type  byte
	Flags byte
	Mask  windows.ACCESS_MASK
	SID   *windows.SID
}

// Grantees are the SIDs the allowed entries name.
func (s Security) Grantees() []*windows.SID {
	var sids []*windows.SID

	for _, e := range s.Entries {
		if e.Type == windows.ACCESS_ALLOWED_ACE_TYPE {
			sids = append(sids, e.SID)
		}
	}

	return sids
}

// ReadSecurity is path's owner and DACL, read by name. A DACL that is not there -- a NULL one, which
// grants everybody everything -- fails tb.
func ReadSecurity(tb testing.TB, path string) Security {
	tb.Helper()

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		tb.Fatal(err)
	}

	owner, _, err := sd.Owner()
	if err != nil {
		tb.Fatal(err)
	}

	control, _, err := sd.Control()
	if err != nil {
		tb.Fatal(err)
	}

	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		tb.Fatalf("the DACL of %s: %v, %v", path, dacl, err)
	}

	s := Security{Owner: owner, Protected: control&windows.SE_DACL_PROTECTED != 0}

	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			tb.Fatal(err)
		}

		s.Entries = append(s.Entries, Entry{Type: ace.Header.AceType, Flags: ace.Header.AceFlags, Mask: ace.Mask,
			SID: (*windows.SID)(unsafe.Pointer(&ace.SidStart))})
	}

	return s
}
