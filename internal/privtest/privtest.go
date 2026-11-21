// Package privtest is scaffolding for Windows tests, and only for tests: a privilege of the
// process's own token for a moment (WithRestore), where an Administrator holds what SYSTEM, which
// the supervisor runs as, may do without asking, and the id a privilege is known by (LUID); the
// SIDs of Users, SYSTEM and the Administrators; a grant to Users, or to any account, beside what a
// DACL holds (GrantUsers, Grant, WithUsers), %ProgramData%'s among them (ProgramDataGrant); a
// temporary directory on a way SYSTEM trusts, whatever the default-owner policy (ServiceTemp); a
// Windows client's default-owner policy for what this process makes (CreatorOwns), and a file's
// owner (SetOwner); a parent that refuses what is made in it a DACL given afterwards
// (DenyOwnersTheirDACL); a file's owner and DACL as a test reads them (ReadSecurity); and a folder
// shared through this machine's own server, a network volume as Windows sees one (Share), and a
// drive mapped to it (MapDrive).
//
// It imports nothing of conflux's, so any package's tests can use it, paths' own among them.
package privtest
