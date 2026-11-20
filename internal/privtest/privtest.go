// Package privtest is scaffolding for Windows tests, and only for tests: a privilege of the
// process's own token for a moment (WithRestore), where an Administrator holds what SYSTEM, which
// the supervisor runs as, may do without asking, and the id a privilege is known by (LUID); a
// grant to Users beside what a DACL holds (GrantUsers, WithUsers); and a file's owner and DACL as
// a test reads them (ReadSecurity).
//
// It imports nothing of conflux's, so any package's tests can use it, paths' own among them.
package privtest
