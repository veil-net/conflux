//go:build windows

package service

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	// ServiceName has no space in it, deliberately. The previous conflux used
	// "VeilNet Conflux" as the service name as well as the display name, which
	// makes every sc.exe invocation quoting-sensitive for no benefit.
	displayName = "VeilNet Conflux"
	description = "Joins this machine to a VeilNet overlay."
)

type scm struct{}

func newManager() (Manager, error) { return scm{}, nil }

// ServiceName is the SCM entry conflux registers.
//
// A function and not a constant because a run rooted in a CONFLUX_DIR is a separate
// installation and must not be registered over the machine's own; see scope.
func ServiceName() string { return "conflux" + scope() }

func (scm) Name() string { return ServiceName() }

func (scm) Install(exe string, args ...string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service manager: %w", err)
	}
	defer m.Disconnect()

	cfg := mgr.Config{
		DisplayName:      displayName,
		Description:      description,
		StartType:        mgr.StartAutomatic,
		ServiceStartName: "LocalSystem",
		Dependencies:     []string{"Tcpip", "Dnscache", "NSI"},
	}

	// Already there is not a failure; it is an upgrade.
	if existing, err := m.OpenService(ServiceName()); err == nil {
		defer existing.Close()

		cfg.BinaryPathName = quoteCommand(exe, args)

		if err := existing.UpdateConfig(cfg); err != nil {
			return fmt.Errorf("update the service: %w", err)
		}

		return recovery(existing)
	}

	// CreateService appends the arguments. The previous conflux omitted them
	// entirely, so the registered service ran conflux with an empty argv tail and
	// fell into the help text at every boot.
	s, err := m.CreateService(ServiceName(), exe, cfg, args...)
	if err != nil {
		return fmt.Errorf("create the service: %w", err)
	}
	defer s.Close()

	return recovery(s)
}

// recovery tells the SCM to restart conflux if it dies, which the previous conflux
// never configured at all.
func recovery(s *mgr.Service) error {
	return s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 86400)
}

func (c scm) Remove() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName())
	if err != nil {
		return nil // already gone, which is what was asked for
	}
	defer s.Close()

	// Best effort: a service that is already stopped refuses the control, and that
	// must not stop the deletion.
	_, _ = s.Control(svc.Stop)

	return s.Delete()
}

func (scm) control(cmd svc.Cmd, want svc.State) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName())
	if err != nil {
		return fmt.Errorf("the conflux service is not registered: %w", err)
	}
	defer s.Close()

	if _, err := s.Control(cmd); err != nil {
		return err
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		status, err := s.Query()
		if err != nil {
			return err
		}

		if status.State == want {
			return nil
		}

		time.Sleep(300 * time.Millisecond)
	}

	return fmt.Errorf("the service did not reach the requested state within 30s")
}

func (scm) Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName())
	if err != nil {
		return fmt.Errorf("the conflux service is not registered: %w", err)
	}
	defer s.Close()

	return s.Start()
}

func (c scm) Stop() error { return c.control(svc.Stop, svc.Stopped) }

func (c scm) Restart() error {
	_ = c.Stop()

	return c.Start()
}

func (scm) Installed() (bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName())
	if err != nil {
		return false, nil
	}

	s.Close()

	return true, nil
}

func (scm) Running() (bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName())
	if err != nil {
		return false, nil
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return false, err
	}

	return status.State == svc.Running || status.State == svc.StartPending, nil
}

func (c scm) Describe() string {
	installed, _ := c.Installed()
	if !installed {
		return "not installed"
	}

	running, _ := c.Running()
	if running {
		return fmt.Sprintf("running (service: %s, automatic at boot)", ServiceName())
	}

	return fmt.Sprintf("installed, not running (service: %s, automatic at boot)", ServiceName())
}

// quoteCommand renders a BinaryPathName the SCM will parse back correctly.
func quoteCommand(exe string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, `"`+exe+`"`)

	for _, a := range args {
		if strings.ContainsAny(a, ` "`) {
			a = `"` + strings.ReplaceAll(a, `"`, `\"`) + `"`
		}

		parts = append(parts, a)
	}

	return strings.Join(parts, " ")
}
