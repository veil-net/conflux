//go:build freebsd || openbsd

package paths

import "runtime"

const sockPathMax = 104 // sizeof(sockaddr_un.sun_path) on the BSDs

// writesLog is FreeBSD's: its daemon(8) writes the service's output to a file, where
// OpenBSD's rc.d sends it to syslog.
const writesLog = runtime.GOOS == "freebsd"

// platformRoot is in /var/db, where the BSDs keep a service's state.
func platformRoot() string { return "/var/db/.conflux" }
