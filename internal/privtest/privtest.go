// Package privtest is for tests that need a privilege of the process's own token for a moment,
// and only for tests: Windows's, where an Administrator holds what SYSTEM, which the supervisor
// runs as, may do without asking.
//
// It imports nothing of conflux's, so any package's tests can use it, paths' own among them.
package privtest
