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

	if err := sup.Dirs.EnsureAll(); err != nil {
		return true, ExitError
	}

	if f, err := os.OpenFile(sup.Dirs.LogFile(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		defer f.Close()

		ui.Out, ui.Errw = f, f
	}

	h := &handler{sup: sup}

	if err := svc.Run(service.ServiceName(), h); err != nil {
		return true, ExitError
	}

	return true, h.code
}

type handler struct {
	sup  *daemon.Supervisor
	code int
}

// Execute is the SCM's view of conflux.
//
// A stop cancels the supervisor's context, which runs its full shutdown -- close the
// anchor so it says goodbye, then signal, then kill -- rather than reporting Stopped
// and leaving peers to discover the departure by timeout. Stop is accepted from the
// start: a bring-up can take ninety seconds, or keep failing, and `conflux down`, a
// restart and `uninstall` must not wait it out.
func (h *handler) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

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

				s <- svc.Status{State: svc.Stopped}

				return false, 0
			}
		case err := <-errc:
			h.code = supervisorExit(err)
			s <- svc.Status{State: svc.Stopped}

			return false, 1
		}
	}
}
