//go:build windows

package config

import (
	"errors"

	"golang.org/x/sys/windows"
)

var errUnsupportedDirSync = errors.New("directories cannot be synced on windows")

// restrictToAdmins is what 0600 means on Windows, which is nothing.
//
// A Go program that calls Chmod(0600) here has changed only the read-only bit. The
// file inherits %ProgramData%'s DACL, and that grants Users read -- so the identity
// seed, which is the whole of the machine's overlay identity and cannot be revoked,
// would be readable by every account on the box.
//
// Replace the DACL outright with two entries, SYSTEM and Administrators, and turn
// inheritance off so the parent's grant to Users cannot come back.
func restrictToAdmins(path string) error {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}

	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}

	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(system),
			},
		},
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(admins),
			},
		},
	}, nil)
	if err != nil {
		return err
	}

	// PROTECTED_DACL_SECURITY_INFORMATION is the half that matters: without it the
	// inherited ACEs are merged back in and the restriction is cosmetic.
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	)
}
