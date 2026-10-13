//go:build windows

package service

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/veil-net/conflux/internal/paths"
)

// The display name has a space in it and the service name does not, deliberately: a
// name with one makes every sc.exe invocation quoting-sensitive for no benefit.
const (
	displayName = "VeilNet Conflux"
	description = "Joins this machine to a VeilNet overlay."
)

type scm struct{}

func newManager() Manager { return scm{} }

// ServiceName is the SCM entry conflux registers.
//
// A function and not a constant because a run rooted in a CONFLUX_DIR is a separate
// installation and must not be registered over the machine's own; see scope.
func ServiceName() string { return "conflux" + scope() }

func (scm) Install(exe string, args ...string) error {
	m, err := connect(windows.SC_MANAGER_ALL_ACCESS)
	if err != nil {
		return err
	}
	defer m.Disconnect()

	// ServiceType named, not left zero: CreateService fills it in, but UpdateConfig hands
	// it to ChangeServiceConfig as it is, which refuses a zero type, so every re-run of
	// up would fail to re-register an existing service.
	cfg := mgr.Config{
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		DisplayName:      displayName,
		Description:      description,
		StartType:        mgr.StartAutomatic,
		ServiceStartName: "LocalSystem",
		Dependencies:     []string{"Tcpip", "Dnscache", "NSI"},
	}

	// Already there is not a failure; it is an upgrade.
	if existing, err := m.OpenService(ServiceName()); err == nil {
		defer existing.Close()

		// Composed the way CreateService composes it below, so an upgrade registers the
		// same command line a fresh install would.
		cfg.BinaryPathName = windows.ComposeCommandLine(append([]string{exe}, args...))

		if err := existing.UpdateConfig(cfg); err != nil {
			return fmt.Errorf("update the service: %w", err)
		}

		return recovery(existing)
	}

	// CreateService appends the arguments -- `serve`, and the root of a CONFLUX_DIR run.
	s, err := m.CreateService(ServiceName(), exe, cfg, args...)
	if err != nil {
		return fmt.Errorf("create the service: %w", err)
	}
	defer s.Close()

	return recovery(s)
}

// recovery tells the SCM to restart conflux when it fails: when it dies, and when it
// stops with an error -- the supervisor's exit 1, a failure the next start may not meet,
// which without the non-crash flag the SCM would record and leave stopped. A supervisor
// that ends on nothing to start, or on a configuration no restart changes, stops without
// one (cli.scmExit), so it is not restarted into the same answer. The last action repeats.
func recovery(s *mgr.Service) error {
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 86400); err != nil {
		return err
	}

	return s.SetRecoveryActionsOnNonCrashFailures(true)
}

// connect opens the service manager with the access given: all of it for the verbs that
// change the service, and only what a status needs for the ones that read it, which an
// account that is not an administrator is also granted.
func connect(access uint32) (*mgr.Mgr, error) {
	h, err := windows.OpenSCManager(nil, nil, access)
	if err != nil {
		return nil, fmt.Errorf("connect to the service manager: %w", err)
	}

	return &mgr.Mgr{Handle: h}, nil
}

// withService runs f on the conflux service, opened with access, from a service manager
// connected with scAccess. A service that is not registered is ERROR_SERVICE_DOES_NOT_EXIST.
func withService(scAccess, access uint32, f func(*mgr.Service) error) error {
	m, err := connect(scAccess)
	if err != nil {
		return err
	}
	defer m.Disconnect()

	name := ServiceName()

	h, err := windows.OpenService(m.Handle, windows.StringToUTF16Ptr(name), access)
	if err != nil {
		return err
	}

	s := &mgr.Service{Name: name, Handle: h}
	defer s.Close()

	return f(s)
}

// stopService stops the service and returns once its process has gone, so that what
// comes next -- a start, the deletion, removing the directory conflux.exe and its log are
// in -- never meets the old one still running. Already stopped is success.
//
// The SCM reports Stopped from inside the process, before it exits: waiting for the state
// alone would race the process for its own files. Its handle is opened before the stop is
// asked for, and kept only if the service still names that pid after, so it cannot be a
// process given the pid since.
func stopService(s *mgr.Service) error {
	status, err := s.Query()
	if err != nil {
		return err
	}

	if status.State == svc.Stopped {
		return nil
	}

	var proc windows.Handle

	if status.ProcessId != 0 {
		if h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, status.ProcessId); err == nil {
			defer windows.CloseHandle(h)

			if again, err := s.Query(); err == nil && again.ProcessId == status.ProcessId {
				proc = h
			}
		}
	}

	// The handler's own stop budget is thirty seconds; the rest is the process's exit.
	deadline := time.Now().Add(45 * time.Second)

	for asked := false; ; time.Sleep(300 * time.Millisecond) {
		if !asked {
			switch _, err := s.Control(svc.Stop); {
			case err == nil, errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE):
				asked = true
			case errors.Is(err, windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL):
				// Between states; asked again on the next round.
			default:
				return err
			}
		}

		status, err := s.Query()
		if err != nil {
			return err
		}

		if status.State == svc.Stopped {
			break
		}

		if time.Now().After(deadline) {
			return errors.New("the service did not stop within 45s")
		}
	}

	if proc != 0 {
		wait := max(time.Until(deadline), time.Second)

		if event, err := windows.WaitForSingleObject(proc, uint32(wait.Milliseconds())); err != nil || event != windows.WAIT_OBJECT_0 {
			return errors.New("the service reported it had stopped and its process did not exit")
		}
	}

	return nil
}

func (scm) Remove() error {
	err := withService(windows.SC_MANAGER_ALL_ACCESS, windows.SERVICE_ALL_ACCESS, func(s *mgr.Service) error {
		// Best effort: the deletion goes ahead whatever the stop says, and a service still
		// running is deleted once it stops.
		_ = stopService(s)

		return s.Delete()
	})
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil // already gone, which is what was asked for
	}

	return err
}

func (scm) Stop() error {
	return notRegistered(withService(windows.SC_MANAGER_ALL_ACCESS, windows.SERVICE_ALL_ACCESS, stopService))
}

func (scm) Restart() error {
	return notRegistered(withService(windows.SC_MANAGER_ALL_ACCESS, windows.SERVICE_ALL_ACCESS, func(s *mgr.Service) error {
		_ = stopService(s)

		return s.Start()
	}))
}

func notRegistered(err error) error {
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return fmt.Errorf("the conflux service is not registered: %w", err)
	}

	return err
}

func (scm) Installed() (bool, error) {
	err := withService(windows.SC_MANAGER_CONNECT, windows.SERVICE_QUERY_STATUS, func(*mgr.Service) error { return nil })

	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST):
		return false, nil
	default:
		return false, err
	}
}

// Describe asks the SCM once whether the service exists and whether it runs.
func (scm) Describe() string {
	var described string

	err := withService(windows.SC_MANAGER_CONNECT, windows.SERVICE_QUERY_STATUS, func(s *mgr.Service) error {
		described = fmt.Sprintf("installed, not running (service: %s, automatic at boot)", ServiceName())

		if status, err := s.Query(); err == nil && (status.State == svc.Running || status.State == svc.StartPending) {
			described = fmt.Sprintf("running (service: %s, automatic at boot)", ServiceName())
		}

		return nil
	})

	switch {
	case err == nil:
		return described
	case errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST):
		return "not installed"
	default:
		return "unknown: " + err.Error()
	}
}

// LogHint is the file the service writes its output to. It lives under the conflux
// root, so uninstall removes it with the rest and Remove has nothing of its own to.
func (scm) LogHint() string {
	return `Get-Content -Tail 50 "` + paths.Default().LogFile() + `"`
}
