package cli

import (
	"os"

	"github.com/veil-net/conflux/internal/service"
	"github.com/veil-net/conflux/internal/ui"
)

// launchdExit is the supervisor's exit as launchd is told it. launchd can name no exit code
// that should not restart, so a job whose KeepAlive restarts every failure would start one
// with nothing to start (78), or that gave up for good (70), every ThrottleInterval for ever:
// a Mac that ran `conflux install` and was never configured, from every boot. Under launchd
// those two are a clean exit, which KeepAlive leaves stopped, as the Windows SCM is told; the
// log has said why. Anything else, and a supervisor launchd did not start, is as it was.
func launchdExit(code int) int {
	if (code == ExitNoConfig || code == ExitChildFailed) && os.Getenv("XPC_SERVICE_NAME") == service.Label() {
		ui.Errf("stopped, and launchd is told the exit was clean (it was %d), so it does not start this again "+
			"into the same answer; conflux up, proxy, observe or start starts it", code)

		return ExitOK
	}

	return code
}
