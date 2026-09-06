//go:build linux

package libexec

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// clearQuarantine is a macOS concern; Linux has no such attribute.
func clearQuarantine(string) {}

// cannotExecute names the two things that stop a 0700 file owned by the caller from
// running, because the kernel's message for both is "permission denied" and neither
// is guessable from it. This is the single most confusing failure conflux can hit.
func cannotExecute(dir string) string {
	msg := fmt.Sprintf("the anchor binaries were extracted to %s but will not run from there.", dir)

	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err == nil && st.Flags&unix.MS_NOEXEC != 0 {
		return msg + "\n  that filesystem is mounted noexec.\n" +
			"  set CONFLUX_DIR to a directory on a filesystem that allows execution."
	}

	if b, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil && len(b) > 0 && b[0] == '1' {
		return msg + "\n  SELinux is enforcing, and a binary under this path is probably labelled var_lib_t.\n" +
			"  try:  sudo semanage fcontext -a -t bin_t '" + dir + "(/.*)?' && sudo restorecon -R " + dir + "\n" +
			"  or set CONFLUX_DIR to a directory execution is permitted from."
	}

	return msg + "\n  check that the filesystem is not mounted noexec, and that no policy forbids execution there."
}
