package privtest

import (
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

	name, err := windows.UTF16PtrFromString("SeRestorePrivilege")
	if err != nil {
		tb.Fatal(err)
	}

	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		tb.Fatal(err)
	}

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

// Users is BUILTIN\Users, every account on the machine.
var Users = func() *windows.SID {
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		panic("privtest: " + err.Error())
	}

	return sid
}()

// GrantUsers gives Users access to path, beside what its DACL grants already, passed on to what
// path holds as inherit says: its DACL read and written by name, so through a link or a junction
// it is the DACL of where it leads.
func GrantUsers(tb testing.TB, path string, access windows.ACCESS_MASK, inherit uint32) {
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
		nil, nil, WithUsers(tb, dacl, access, inherit), nil); err != nil {
		tb.Fatal(err)
	}
}

// WithUsers is dacl with access granted to Users on the object itself, and passed on as inherit
// says, merged in as SetEntriesInAcl merges an entry.
func WithUsers(tb testing.TB, dacl *windows.ACL, access windows.ACCESS_MASK, inherit uint32) *windows.ACL {
	tb.Helper()

	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: access,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inherit,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(Users),
		},
	}}, dacl)
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

// Entry is one ACE: its type, and the SID it names.
type Entry struct {
	Type byte
	SID  *windows.SID
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

		s.Entries = append(s.Entries, Entry{ace.Header.AceType, (*windows.SID)(unsafe.Pointer(&ace.SidStart))})
	}

	return s
}
