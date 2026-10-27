package daemon

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
	"golang.org/x/sys/windows"
)

// On Windows anchord runs in userspace mode as LOCAL SERVICE, logged on by the supervisor
// with conflux's own service SID added as a group, every privilege but SeChangeNotify
// removed, and a default DACL that names only SYSTEM and that SID -- so what it creates,
// and the process itself, are reachable by nothing else that runs as LOCAL SERVICE. A TUN
// needs SYSTEM, for wintun, and gets it.

// openUntrusted is what a file in the account's directory is opened with.
const openUntrusted = os.O_RDONLY

// workDir leaves anchord where a service's child starts.
const workDir = ""

// dropState holds the token the next anchord is started with, from dropTo to the start,
// and the sets anchord -h has started from under one.
type dropState struct {
	token  windows.Token
	smoked map[string]bool
}

// windowsServiceName is the SCM name of this installation's service, as
// service.ServiceName registers it: conflux, with a CONFLUX_DIR installation's scope.
func windowsServiceName() string { return "conflux" + paths.Scope() }

var (
	advapi32                  = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUserExExW        = advapi32.NewProc("LogonUserExExW")
	procCreateRestrictedToken = advapi32.NewProc("CreateRestrictedToken")
)

const (
	logon32LogonService    = 5 // LOGON32_LOGON_SERVICE
	logon32ProviderDefault = 0
	disableMaxPrivilege    = 0x1 // DISABLE_MAX_PRIVILEGE: all privileges but SeChangeNotify removed

	// The account's rights on the two directories it is given, on the directory itself:
	// list, traverse, create files and subdirectories, delete what is in it, read and
	// write attributes -- and not DELETE, WRITE_DAC or WRITE_OWNER on it.
	dirOwnRights = "0x1201ff"
)

// dropTo makes the token anchord runs as, and checks that anchord starts under it.
func (s *Supervisor) dropTo(p *Privilege) string {
	sid, err := windows.StringToSid(serviceSID(windowsServiceName()))
	if err != nil {
		return "could not form the service's SID: " + err.Error()
	}

	tok, err := localServiceToken(sid)
	if err != nil {
		s.report().Warn("could not log anchord on as LOCAL SERVICE: %v", err)

		return "the supervisor could not log anchord on as LOCAL SERVICE: " + firstLine(err)
	}

	s.releaseDrop()
	s.drop.token = tok

	p.As = `NT AUTHORITY\LOCAL SERVICE`

	for _, g := range []struct {
		path   string
		access windows.ACCESS_MASK
	}{
		{s.tools.Dir, windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE},
		{s.tools.Anchord, windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE},
	} {
		if err := grantSID(g.path, sid, g.access); err != nil {
			s.releaseDrop()

			return "could not let LOCAL SERVICE run anchord: " + firstLine(err)
		}
	}

	if err := s.smoke(*p); err != nil {
		s.report().Warn("%v", err)
		s.releaseDrop()

		return "anchord does not start as LOCAL SERVICE on this host: " + firstLine(err)
	}

	return ""
}

// localServiceToken logs LOCAL SERVICE on with the service SID added, and takes every
// privilege but SeChangeNotify out of it: LOCAL SERVICE holds SeImpersonate, which is the
// well-known way back to SYSTEM, and a privilege merely disabled can be enabled again.
func localServiceToken(sid *windows.SID) (windows.Token, error) {
	if err := enablePrivileges("SeTcbPrivilege", "SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege"); err != nil {
		return 0, err
	}

	if err := procLogonUserExExW.Find(); err != nil {
		return 0, err
	}

	groups := windows.Tokengroups{GroupCount: 1}
	groups.Groups[0] = windows.SIDAndAttributes{
		Sid: sid,
		Attributes: windows.SE_GROUP_MANDATORY | windows.SE_GROUP_ENABLED_BY_DEFAULT |
			windows.SE_GROUP_ENABLED | windows.SE_GROUP_OWNER,
	}

	user, _ := windows.UTF16PtrFromString("LocalService")
	domain, _ := windows.UTF16PtrFromString("NT AUTHORITY")

	var logon windows.Token

	r, _, err := procLogonUserExExW.Call(
		uintptr(unsafe.Pointer(user)), uintptr(unsafe.Pointer(domain)), 0,
		logon32LogonService, logon32ProviderDefault,
		uintptr(unsafe.Pointer(&groups)), uintptr(unsafe.Pointer(&logon)), 0, 0, 0, 0)
	if r == 0 {
		return 0, fmt.Errorf("LogonUserExExW: %w", err)
	}
	defer logon.Close()

	return restrictToken(logon, sid)
}

// restrictToken is tok with every privilege but SeChangeNotify removed -- removed, not
// disabled, so the process it starts cannot enable one again -- with sid as the owner of
// what that process creates, where tok carries sid as a group it may own with, and a
// default DACL that names only SYSTEM and sid.
func restrictToken(tok windows.Token, sid *windows.SID) (windows.Token, error) {
	var restricted windows.Token

	r, _, err := procCreateRestrictedToken.Call(uintptr(tok), disableMaxPrivilege,
		0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted)))
	if r == 0 {
		return 0, fmt.Errorf("CreateRestrictedToken: %w", err)
	}

	// The SID owns what anchord creates, rather than LOCAL SERVICE, whose every other
	// process would otherwise have an owner's rights on it.
	owner := struct{ Owner *windows.SID }{sid}
	_ = windows.SetTokenInformation(restricted, windows.TokenOwner,
		(*byte)(unsafe.Pointer(&owner)), uint32(unsafe.Sizeof(owner)))

	dacl, err := aclFromSDDL("D:(A;;GA;;;SY)(A;;GA;;;" + sid.String() + ")")
	if err == nil {
		info := struct{ DefaultDacl *windows.ACL }{dacl}
		err = windows.SetTokenInformation(restricted, windows.TokenDefaultDacl,
			(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	}

	if err != nil {
		restricted.Close()

		return 0, fmt.Errorf("set the token's default DACL: %w", err)
	}

	return restricted, nil
}

// enablePrivileges turns on, in this process's own token, what logging another account on
// and starting a process as it take. SYSTEM holds all three.
func enablePrivileges(names ...string) error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer tok.Close()

	for _, name := range names {
		var luid windows.LUID

		n, _ := windows.UTF16PtrFromString(name)
		if err := windows.LookupPrivilegeValue(nil, n, &luid); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}

		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}

		// One this process does not hold is not an error here: the logon that needs it
		// refuses, naming it, and anchord runs as the supervisor instead.
		if err := windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}

	return nil
}

func aclFromSDDL(sddl string) (*windows.ACL, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}

	dacl, _, err := sd.DACL()

	return dacl, err
}

// smoke starts anchord -h under the token once for each set: a token the system will not
// start it under -- a window station it may not open, a policy -- says so here, and
// anchord runs as SYSTEM, as it always has.
func (s *Supervisor) smoke(p Privilege) error {
	key := s.tools.SetID
	if s.drop.smoked[key] {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.tools.Anchord, "-h")
	cmd.SysProcAttr = s.procAttrFor(p)
	cmd.Env = anchordEnv(p, "")

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("anchord -h as LOCAL SERVICE: %w\n%s", err, strings.TrimSpace(string(out)))
	}

	if s.drop.smoked == nil {
		s.drop.smoked = map[string]bool{}
	}

	s.drop.smoked[key] = true

	return nil
}

// procAttrFor is anchord's process attributes: its own process group, and for the
// account the token, with a process and thread that SYSTEM, Administrators and the
// service SID may open and nothing else that runs as LOCAL SERVICE may.
func (s *Supervisor) procAttrFor(p Privilege) *syscall.SysProcAttr {
	attr := procAttr()

	if !p.Account || s.drop.token == 0 {
		return attr
	}

	sid := serviceSID(windowsServiceName())
	sd := "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + sid + ")(A;;RC;;;OW)"

	attr.Token = syscall.Token(s.drop.token)
	attr.ProcessAttributes = securityAttributes(sd)
	attr.ThreadAttributes = securityAttributes(sd)

	return attr
}

func securityAttributes(sddl string) *syscall.SecurityAttributes {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil
	}

	return &syscall.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(syscall.SecurityAttributes{})),
		SecurityDescriptor: uintptr(unsafe.Pointer(sd)),
	}
}

// releaseDrop closes the token once the process it was for has started with it.
func (s *Supervisor) releaseDrop() {
	if s.drop.token != 0 {
		s.drop.token.Close()
		s.drop.token = 0
	}
}

func startProcess(cmd *exec.Cmd, _ Privilege) error { return cmd.Start() }

// freshDaemonRun makes anchord's run directory afresh: the service SID's, with its rights
// set as it is created and never propagated over anything the account wrote; SYSTEM's and
// Administrators' alone for a SYSTEM anchord.
func (s *Supervisor) freshDaemonRun(p Privilege) error {
	dir := s.Dirs.DaemonRun()

	if err := os.RemoveAll(dir); err != nil {
		return err
	}

	return makeAnchorDir(dir, p)
}

// killLeftovers is the job's on Windows: each anchord has one of its own, closed when it
// is gone, which ends everything it started.
func (s *Supervisor) killLeftovers() {}

// makeAnchorDir creates path for p's identity, with its security descriptor set as it is
// created.
func makeAnchorDir(path string, p Privilege) error {
	if !p.Account {
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}

		return paths.Restrict(path, true)
	}

	sid := serviceSID(windowsServiceName())
	sddl := "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;" + dirOwnRights + ";;;" + sid + ")" +
		"(A;OICIIO;FA;;;" + sid + ")(A;OICI;RC;;;OW)"

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}

	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	return windows.CreateDirectory(name, &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	})
}

// legacyAnchorDir reports an anchor directory at the account's name that the service SID
// was never given: conflux 1.0.0's, which a SYSTEM anchord used.
func legacyAnchorDir(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.IsDir() {
		return false
	}

	return !grantsServiceSID(path)
}

// anchorDirFor reports whether path is the directory p's identity is given.
func anchorDirFor(path string, p Privilege) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.IsDir() {
		return false
	}

	return !p.Account || grantsServiceSID(path)
}

func grantsServiceSID(path string) bool {
	sid, err := windows.StringToSid(serviceSID(windowsServiceName()))
	if err != nil {
		return false
	}

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}

	dacl, _, err := sd.DACL()

	return err == nil && hasACE(dacl, sid)
}

func hasACE(dacl *windows.ACL, sid *windows.SID) bool {
	if dacl == nil {
		return false
	}

	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, i, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}

		if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(sid) {
			return true
		}
	}

	return false
}

// grantSID adds sid to path's DACL with access, on that object alone. Only ever on what
// SYSTEM and Administrators alone can write -- the set directory, anchord.exe, the
// daemon's configuration -- so nothing is propagated over anything the account wrote.
func grantSID(path string, sid *windows.SID, access windows.ACCESS_MASK) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}

	if hasACE(dacl, sid) {
		return nil
	}

	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: access,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, dacl)
	if err != nil {
		return err
	}

	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// ownFile has nothing to do: a file created in the account's directory inherits its
// grant, and is owned by the SID the token names.
func ownFile(*os.File, Privilege) error { return nil }

// oneLink is not asked on Windows, where linking to a file takes write access to it.
func oneLink(os.FileInfo) bool { return true }

// writeDaemonFile writes anchord's -config: SYSTEM's and Administrators', and readable by
// the service SID when anchord runs as its account.
func writeDaemonFile(path string, data []byte, p Privilege) error {
	if err := config.WriteFileAtomic(path, data, 0o600); err != nil {
		return err
	}

	if !p.Account {
		return nil
	}

	sid, err := windows.StringToSid(serviceSID(windowsServiceName()))
	if err != nil {
		return err
	}

	return grantSID(path, sid, windows.FILE_GENERIC_READ)
}
