// Package privtest is scaffolding for Windows tests, and only for tests: a privilege of the
// process's own token for a moment (WithRestore), where an Administrator holds what SYSTEM, which
// the supervisor runs as, may do without asking, and the id a privilege is known by (LUID); the
// SIDs of Users, SYSTEM and the Administrators; a grant to Users, or to any account, beside what a
// DACL holds (GrantUsers, Grant, WithUsers), %ProgramData%'s among them (ProgramDataGrant); a
// temporary directory only SYSTEM and the Administrators may change (ServiceTemp); a Windows client's default-owner policy
// for what this process makes, in place of the one conflux sets as it starts (CreatorOwns), and a
// file's owner (SetOwner), or its owner and protected DACL as SDDL spells them (SetSecurity); a
// parent that refuses what is made in it a DACL given afterwards
// (DenyOwnersTheirDACL); and a file's owner and DACL as a test reads them (ReadSecurity).
//
// It imports nothing of conflux's, so any package's tests can use it, paths' own among them.
package privtest
