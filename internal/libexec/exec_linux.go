//go:build linux

package libexec

import (
	"fmt"
	"os"

	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privcheck"
)

// cannotExecute names the two things that stop a 0700 file owned by the caller from
// running, because the kernel's message for both is "permission denied" and neither
// is guessable from it. This is the single most confusing failure conflux can hit.
// bin is the directory every set is extracted beneath.
func cannotExecute(bin string) string {
	msg := fmt.Sprintf("the anchor binaries were extracted to %s but will not run from there.", bin)

	if ok, err := paths.MountAllowsExec(bin); err == nil && !ok {
		return msg + "\n  that filesystem is mounted noexec.\n" +
			"  set CONFLUX_DIR to a directory on a filesystem that allows execution."
	}

	if b, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil && len(b) > 0 && b[0] == '1' {
		return msg + "\n" + selinuxHint(bin)
	}

	return msg + "\n  check that the filesystem is not mounted noexec, and that no policy forbids execution there."
}

// selinuxHint is what to do where SELinux is enforcing: label bin, the directory every set is
// extracted beneath, so the next upgrade's set is not refused again, and relabel what is there,
// each command as root runs it and quoted for the shell it is pasted into.
func selinuxHint(bin string) string {
	return "  SELinux is enforcing, and a binary under this path is probably labelled var_lib_t.\n" +
		"  try:  " + privcheck.Retry(privcheck.Command("semanage", "fcontext", "-a", "-t", "bin_t", bin+"(/.*)?")) +
		" && " + privcheck.Retry(privcheck.Command("restorecon", "-R", bin)) + "\n" +
		"  or set CONFLUX_DIR to a directory execution is permitted from."
}
