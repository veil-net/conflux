//go:build !linux && !darwin && !freebsd && !windows

package daemon

// processExe: OpenBSD reports no process's executable, so an orphan is recognised by the
// lock anchord holds on the socket instead; see isOurDaemon.
func processExe(int) (string, error) { return "", errNoExePath }
