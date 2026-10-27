//go:build windows

package cli

import (
	"context"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/service"
	"github.com/veil-net/conflux/internal/ui"
)

// serveAsService hands over to the service control manager when conflux was started
// by it, and reports false when it was started from a console.
//
// A service has no console to write to, so what the supervisor and anchord say goes
// to the log file instead, where `conflux up` points when a start fails.
func serveAsService(sup *daemon.Supervisor) (bool, int) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false, 0
	}

	// Without the directories there is no log to write to, and the SCM still has to be
	// answered: returning without svc.Run leaves it to time the start out with nothing
	// recorded anywhere. So the failure goes to the SCM as the service's exit instead, which
	// the System event log records and the recovery actions retry.
	setup := sup.Dirs.EnsureAll()

	if setup == nil {
		if f, err := os.OpenFile(sup.Dirs.LogFile(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			defer f.Close()

			ui.Out, ui.Errw = f, f
		}
	}

	h := &handler{sup: sup, setup: setup}

	if err := svc.Run(service.ServiceName(), h); err != nil {
		return true, ExitError
	}

	return true, h.code
}

type handler struct {
	sup   *daemon.Supervisor
	setup error
	code  int
}

// scmExit is what the SCM is told when the supervisor ends on its own. Only exit 1, a
// failure the next start may not meet, is a failure to the SCM, and so what its recovery
// actions restart. 78 and 70 -- nothing to start, or a configuration no restart changes --
// end as cleanly as a stop does, or recovery would restart them into the same answer every
// few seconds; the log says why.
func scmExit(code int) (svcSpecific bool, exitCode uint32) {
	if code == ExitError {
		return true, ExitError
	}

	return false, 0
}

// Execute is the SCM's view of conflux.
//
// A stop cancels the supervisor's context, which runs its full shutdown -- close the
// anchor so it says goodbye, then signal, then kill -- rather than reporting Stopped
// and leaving peers to discover the departure by timeout. Stop is accepted from the
// start: a bring-up can take ninety seconds, or keep failing, and `conflux down`, a
// restart and `uninstall` must not wait it out.
//
// svc.Run reports Stopped itself once this returns, carrying what it returns: reporting
// it here as well would tell the SCM the service stopped cleanly before the exit code
// that says otherwise could arrive.
func (h *handler) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	if h.setup != nil {
		h.code = ExitError

		return scmExit(h.code)
	}

	s <- svc.Status{State: svc.StartPending, WaitHint: 90_000, Accepts: accepted}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errc := make(chan error, 1)

	go func() { errc <- h.sup.Run(ctx) }()

	// Running only once the anchor is actually up, or after the wait the SCM was promised.
	// Reporting it at once would make a failed start look like a healthy service until
	// somebody looked. Each fires once, and is then forgotten.
	ready, waited := h.sup.Ready, time.After(90*time.Second)

	for {
		select {
		case <-ready:
			ready, waited = nil, nil
			s <- svc.Status{State: svc.Running, Accepts: accepted}
		case <-waited:
			ready, waited = nil, nil
			s <- svc.Status{State: svc.Running, Accepts: accepted}
		case cr := <-r:
			switch cr.Cmd {
			case svc.Interrogate:
				s <- cr.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending, WaitHint: 30_000}

				cancel()

				select {
				case err := <-errc:
					h.code = supervisorExit(err)
				case <-time.After(30 * time.Second):
				}

				return false, 0
			}
		case err := <-errc:
			h.code = supervisorExit(err)

			return scmExit(h.code)
		}
	}
}

// removeAccount has nothing to remove on Windows: anchord runs as LOCAL SERVICE, which is
// the system's, and the service SID it is given goes with the service.
func removeAccount() error { return nil }
