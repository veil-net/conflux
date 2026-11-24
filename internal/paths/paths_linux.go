//go:build linux

package paths

const sockPathMax = 108 // sizeof(sockaddr_un.sun_path) on Linux

// platformRoot is in /var/lib, the FHS's place for variable state a program maintains,
// rather than /usr/libexec for the extracted binaries, because /usr is read-only in
// image-based and container deployments.
func platformRoot() string { return "/var/lib/.conflux" }
