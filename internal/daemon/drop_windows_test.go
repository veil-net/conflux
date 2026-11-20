package daemon

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privtest"
	"golang.org/x/sys/windows"
)

// TestRestrictTokenRemovesPrivileges: the token anchord is started with keeps no privilege
// but SeChangeNotify -- above all not SeImpersonate, the way back to SYSTEM that LOCAL
// SERVICE holds -- and its default DACL names SYSTEM and the service's SID alone. Asked of
// this process's own token, which on an Administrator's runner holds SeImpersonate too: the
// logon itself needs SYSTEM, and the restriction is the same either way.
func TestRestrictTokenRemovesPrivileges(t *testing.T) {
	var own windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ALL_ACCESS, &own); err != nil {
		t.Fatal(err)
	}
	defer own.Close()

	sid, err := paths.ServiceSID()
	if err != nil {
		t.Fatal(err)
	}

	tok, err := restrictToken(own, sid)
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Close()

	notify := privtest.LUID(t, "SeChangeNotifyPrivilege")
	impersonate := privtest.LUID(t, "SeImpersonatePrivilege")

	held := privileges(t, tok)
	for _, luid := range held {
		switch luid {
		case impersonate:
			t.Error("the restricted token still holds SeImpersonatePrivilege")
		case notify:
		default:
			t.Errorf("the restricted token still holds privilege %v", luid)
		}
	}

	if len(held) > 1 {
		t.Errorf("the restricted token holds %d privileges, want SeChangeNotify alone", len(held))
	}

	b := tokenInfo(t, tok, windows.TokenDefaultDacl)
	dacl := (*struct{ DefaultDacl *windows.ACL })(unsafe.Pointer(&b[0])).DefaultDacl

	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if !hasACE(dacl, sid) || !hasACE(dacl, system) || dacl.AceCount != 2 {
		t.Errorf("the default DACL has %d entries, want SYSTEM and the service's SID alone", dacl.AceCount)
	}
}

// TestNewLogonSIDIsOneOfItsOwn: the logon SID anchord's logon is given ahead of the
// service SID is a logon SID, S-1-5-5-X-Y, and a fresh one each time it is drawn.
func TestNewLogonSIDIsOneOfItsOwn(t *testing.T) {
	a, err := newLogonSID()
	if err != nil {
		t.Fatal(err)
	}

	b, err := newLogonSID()
	if err != nil {
		t.Fatal(err)
	}

	for _, sid := range []*windows.SID{a, b} {
		if s := sid.String(); !strings.HasPrefix(s, "S-1-5-5-") || strings.Count(s, "-") != 5 {
			t.Errorf("newLogonSID is %s, want S-1-5-5-X-Y", sid)
		}
	}

	if a.Equals(b) {
		t.Errorf("newLogonSID drew %s twice", a)
	}
}

// privileges are the privileges tok holds, enabled or not.
func privileges(t *testing.T, tok windows.Token) []windows.LUID {
	t.Helper()

	b := tokenInfo(t, tok, windows.TokenPrivileges)
	tp := (*windows.Tokenprivileges)(unsafe.Pointer(&b[0]))

	held := make([]windows.LUID, 0, tp.PrivilegeCount)
	for _, p := range tp.AllPrivileges() {
		held = append(held, p.Luid)
	}

	return held
}

func tokenInfo(t *testing.T, tok windows.Token, class uint32) []byte {
	t.Helper()

	var n uint32
	_ = windows.GetTokenInformation(tok, class, nil, 0, &n)

	b := make([]byte, n)
	if err := windows.GetTokenInformation(tok, class, &b[0], n, &n); err != nil {
		t.Fatal(err)
	}

	return b
}

// TestAServiceSIDNotGivenIsNotOneZeroZero: an anchor directory the service SID was wanted for,
// where Windows did not give it, reads as an error, which the next start reads again -- never as
// conflux 1.0.0's layout, which the supervisor refuses for good, naming a new identity. That the
// failure is not kept is paths.ServiceSID's (TestAServiceSIDNotGivenIsNotKept).
func TestAServiceSIDNotGivenIsNotOneZeroZero(t *testing.T) {
	t.Cleanup(func() { ourServiceSID = paths.ServiceSID })

	ourServiceSID = func() (*windows.SID, error) { return nil, errors.New("RtlCreateServiceSid: STATUS_NO_MEMORY") }

	if legacy, err := legacyAnchorDir(t.TempDir()); legacy || err == nil {
		t.Errorf("legacyAnchorDir = %v, %v with no service SID to read it for; want an error, not 1.0.0's", legacy, err)
	}

	ourServiceSID = paths.ServiceSID

	// A directory the SID was never given, read with the SID in hand, is 1.0.0's.
	if legacy, err := legacyAnchorDir(t.TempDir()); !legacy || err != nil {
		t.Errorf("legacyAnchorDir = %v, %v for a directory the service SID was never given; want 1.0.0's", legacy, err)
	}
}

// TestMakeAnchorDirSetsItsDACLAsItIsMade: an anchor directory is made with its security set as it
// is created (paths.MakeDir), never holding what its parent passes on -- here Users' right to add
// to, and write the attributes and extended attributes of, every folder made in it, as
// %ProgramData% passes on, and a denial of WRITE_DAC to whoever owns it, which a directory made and
// then given its DACL would be refused that by. That pins a SYSTEM anchord's, SYSTEM's and the
// Administrators' alone, as Restrict makes one. An account's, granting the service SID besides, is
// SYSTEM's, which only a process with SeRestorePrivilege enabled may name, and that privilege grants
// WRITE_DAC whatever the denial, so of it only the DACL it ends with is checked, not that it was set
// as it was made. One already there is not made again. Windows-only, so it runs in CI's platforms
// job alone.
func TestMakeAnchorDirSetsItsDACLAsItIsMade(t *testing.T) {
	system, admins := wellKnownSID(t, windows.WinLocalSystemSid), wellKnownSID(t, windows.WinBuiltinAdministratorsSid)

	parent := t.TempDir()
	privtest.GrantUsers(t, parent, windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA|windows.FILE_WRITE_EA|
		windows.FILE_WRITE_ATTRIBUTES, windows.SUB_CONTAINERS_ONLY_INHERIT)
	privtest.DenyOwnersTheirDACL(t, parent)

	root := filepath.Join(parent, "anchor.root")
	if err := makeAnchorDir(root, Privilege{}); err != nil {
		t.Fatalf("makeAnchorDir for a SYSTEM anchord: %v", err)
	}

	if err := makeAnchorDir(root, Privilege{}); !errors.Is(err, fs.ErrExist) {
		t.Errorf("makeAnchorDir of a directory already there = %v, want it refused as there", err)
	}

	// An account's is SYSTEM's, which only a process that may name any owner can make it.
	account := filepath.Join(parent, "anchor")
	if err := privtest.WithRestore(t, func() error { return makeAnchorDir(account, Privilege{Account: true}) }); err != nil {
		t.Fatalf("makeAnchorDir for anchord's account: %v", err)
	}

	sid, err := ourServiceSID()
	if err != nil {
		t.Fatal(err)
	}

	for path, granted := range map[string][]*windows.SID{root: {system, admins}, account: {system, admins, sid}} {
		sec := privtest.ReadSecurity(t, path)

		if !sec.Owner.Equals(system) && !sec.Owner.Equals(admins) {
			t.Errorf("%s belongs to %v, want SYSTEM or the Administrators", path, sec.Owner)
		}

		if !sec.Protected {
			t.Errorf("the DACL of %s is not protected", path)
		}

		seen := map[string]bool{}

		for _, e := range sec.Entries {
			if e.Type != windows.ACCESS_ALLOWED_ACE_TYPE || e.SID.Equals(privtest.Users) {
				t.Errorf("the DACL of %s holds what its parent passes on: an entry of type %d for %s", path, e.Type, e.SID)
			}

			seen[e.SID.String()] = true
		}

		for _, want := range granted {
			if !seen[want.String()] {
				t.Errorf("the DACL of %s does not grant %s", path, want)
			}
		}
	}

	if granted, err := grantsServiceSID(root); err != nil || granted {
		t.Errorf("grantsServiceSID(a SYSTEM anchord's directory) = %v, %v; want false", granted, err)
	}
}

func wellKnownSID(t *testing.T, kind windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	t.Helper()

	sid, err := windows.CreateWellKnownSid(kind)
	if err != nil {
		t.Fatal(err)
	}

	return sid
}
