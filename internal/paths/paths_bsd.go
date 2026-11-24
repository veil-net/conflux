//go:build freebsd || openbsd

package paths

const sockPathMax = 104 // sizeof(sockaddr_un.sun_path) on the BSDs

// platformRoot is in /var/db, where the BSDs keep a service's state.
func platformRoot() string { return "/var/db/.conflux" }
