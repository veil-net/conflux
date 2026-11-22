package paths

import (
	"fmt"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

// rtlCreateServiceSid is ntdll's: the SID Windows gives a service, from its name alone.
var rtlCreateServiceSid = ntdll.NewProc("RtlCreateServiceSid")

// securityMaxSIDSize is SECURITY_MAX_SID_SIZE, room for any SID.
const securityMaxSIDSize = 68

// ServiceName is the name the installation's service is registered under, and its SID (ServiceSID)
// is Windows's for.
const ServiceName = "conflux"

// ServiceSID is serviceSID of the installation's service, ServiceName, kept once Windows has
// given it: its name is fixed, and a start needs the SID in several places -- the token, anchord's directory and the -config's grant. A failure is
// not kept, so the next start asks again rather than going without the SID, or refusing, for the
// rest of the process.
func ServiceSID() (*windows.SID, error) {
	if sid := serviceSIDKept.Load(); sid != nil {
		return sid, nil
	}

	sid, err := askServiceSID()
	if err != nil {
		return nil, err
	}

	serviceSIDKept.Store(sid)

	return sid, nil
}

// serviceSIDKept is the SID ServiceSID was given.
var serviceSIDKept atomic.Pointer[windows.SID]

// askServiceSID asks Windows for the SID: a variable, so a test can be a host whose answer fails.
var askServiceSID = func() (*windows.SID, error) { return serviceSID(ServiceName) }

// serviceSID is NT SERVICE\name, the SID of conflux's own service, which nothing but this
// installation's anchord is ever given on Windows: the one identity its files and its
// process are granted to, in place of LOCAL SERVICE, which many services share.
//
// Asked of Windows rather than computed. The derivation is S-1-5-80 and the SHA-1 of the
// upper-cased name, and SHA-1 is not an algorithm this program uses: conflux runs in FIPS
// 140-3 mode, and nothing it computes itself rests on one the module does not approve
// (docs/security.md, "FIPS 140-3 and CMVP"). RtlCreateServiceSid answers for a name whether
// or not the service exists yet, which is what the computation was for.
func serviceSID(name string) (*windows.SID, error) {
	u, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, fmt.Errorf("the service SID of %q: %w", name, err)
	}

	buf := make([]byte, securityMaxSIDSize)
	n := uint32(len(buf))

	r, _, _ := rtlCreateServiceSid.Call(
		uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if status := windows.NTStatus(r); status != windows.STATUS_SUCCESS {
		return nil, fmt.Errorf("the service SID of %q: RtlCreateServiceSid: %w", name, status)
	}

	return (*windows.SID)(unsafe.Pointer(&buf[0])).Copy()
}
