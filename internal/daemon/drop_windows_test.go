package daemon

import (
	"strings"
	"testing"
	"unsafe"

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

	sid, err := windows.StringToSid(serviceSID("conflux"))
	if err != nil {
		t.Fatal(err)
	}

	tok, err := restrictToken(own, sid)
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Close()

	notify := privilegeLUID(t, "SeChangeNotifyPrivilege")
	impersonate := privilegeLUID(t, "SeImpersonatePrivilege")

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

func privilegeLUID(t *testing.T, name string) windows.LUID {
	t.Helper()

	var luid windows.LUID

	n, _ := windows.UTF16PtrFromString(name)
	if err := windows.LookupPrivilegeValue(nil, n, &luid); err != nil {
		t.Fatal(err)
	}

	return luid
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
