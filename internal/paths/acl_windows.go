package paths

import (
	"errors"
	"fmt"

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
// cannot name Administrators as an owner -- one that is not elevated, which conflux
// never is outside a test -- keeps its own ownership and still gets the DACL. Protected
// is the half that matters for the DACL: without it the parent's ACEs are merged back
// in and the restriction is cosmetic.
func Restrict(path string, dir bool) error {
	inherit := uint32(windows.NO_INHERITANCE)
	if dir {
		inherit = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}

	grant := func(sid *windows.SID, kind windows.TRUSTEE_TYPE) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inherit,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  kind,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}

	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		grant(sidSystem, windows.TRUSTEE_IS_USER),
		grant(sidAdmins, windows.TRUSTEE_IS_GROUP),
	}, nil)
	if err != nil {
		return err
	}

	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)

	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info|windows.OWNER_SECURITY_INFORMATION, sidAdmins, nil, acl, nil)
	if errors.Is(err, windows.ERROR_INVALID_OWNER) {
		err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, acl, nil)
	}

	return err
}

// Trusted reports whether path is owned by SYSTEM, Administrators or the account
// running conflux -- by somebody who could have written it anyway. Restrict makes
// Administrators the owner of everything conflux writes, so another owner is another
// account's file, and whoever owns a file can grant themselves the right to change it:
// a binary about to run as SYSTEM, found with such an owner, is not run.
func Trusted(path string) bool {
	owner, _, err := ownership(path)

	return err == nil && (owner.Equals(sidSystem) || owner.Equals(sidAdmins) || isCurrentUser(owner))
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
// account made.
//
// A directory conflux did not create is one somebody else may have filled before it
// looked -- with a binary for the service to run, or a manifest whose key they hold --
// and taking it over would adopt whatever is inside. The account running conflux is
// accepted as well as SYSTEM and Administrators: an administrator's own directory,
// under a policy that makes the creator its owner, is repaired rather than refused.
func secure(dir string) error {
	owner, control, err := ownership(dir)
	if err != nil {
		return fmt.Errorf("read the ownership of %s: %w", dir, err)
	}

	admin := owner.Equals(sidSystem) || owner.Equals(sidAdmins)
	if admin && control&windows.SE_DACL_PROTECTED != 0 {
		return nil
	}

	if !admin && !isCurrentUser(owner) {
		account, domain, _, _ := owner.LookupAccount("")

		return fmt.Errorf(
			"%s belongs to %s\\%s (%s), which is not an administrator, so conflux did not create it and will not "+
				"use what is in it.\n  Remove it, then run this again as Administrator. If it is left over from "+
				"conflux itself, running any conflux command as that account once repairs it",
			dir, domain, account, owner)
	}

	return Restrict(dir, true)
}

func isCurrentUser(sid *windows.SID) bool {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()

	return err == nil && user.User.Sid.Equals(sid)
}
