//go:build !linux && !windows

package account

import (
	"fmt"
	"os/exec"
	"strconv"
	"time"
)

// Kill ends every process running as uid, and returns once none is left. See the Linux
// one for why; here the base system's pkill and pgrep, which macOS, FreeBSD and OpenBSD
// all ship, do the finding.
func Kill(uid int) error {
	id := strconv.Itoa(uid)

	for round := 0; round < 50; round++ {
		// pgrep exits 1 when nothing matched.
		if err := exec.Command("pgrep", "-U", id).Run(); err != nil {
			if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 1 {
				return nil
			}

			return fmt.Errorf("pgrep -U %s: %w", id, err)
		}

		_ = exec.Command("pkill", "-KILL", "-U", id).Run()

		time.Sleep(20 * time.Millisecond)
	}

	return fmt.Errorf("processes of uid %d are still running", uid)
}
