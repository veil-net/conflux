//go:build linux

package service

import (
	"fmt"
	"os"
	"strings"
)

// unitName is used everywhere, once.
//
// The previous conflux wrote veilnet.service and then started, stopped and removed
// "veilnet". That worked only because systemd appends .service to a bare name, and
// would have broken silently the day anyone added a veilnet.socket beside it.
const unitName = "conflux.service"

const unitPath = "/etc/systemd/system/" + unitName

// unitTemplate is the unit conflux writes.
//
// Type=notify, with sd_notify from the supervisor, is what makes `systemctl start`
// return only once the anchor is actually up rather than once fork succeeded.
//
// RestartPreventExitStatus=78 is the no-configuration case. `conflux serve` exits 78
// when there is nothing to start, and without this the unit would restart into the
// same emptiness every five seconds forever.
//
// Restart=on-failure rather than always, so a deliberate clean exit stays exited.
//
// RuntimeDirectory, StateDirectory and ConfigurationDirectory make systemd create
// and mode the three directories, and clean /run/conflux on stop. conflux still
// creates them itself, so running in the foreground and on non-systemd hosts works.
//
// Deliberately absent: PrivateTmp, because nothing conflux does touches /tmp and it
// would only confuse the extraction path; and ProtectSystem=strict, which would need
// a ReadWritePaths list and would break pass-through writes such as
// `conflux keygen -out ~/key`.
const unitTemplate = `[Unit]
Description=Conflux — VeilNet anchor
Documentation=https://github.com/veil-net/conflux
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
NotifyAccess=main
ExecStart=%s
Restart=on-failure
RestartSec=5
RestartPreventExitStatus=78
TimeoutStartSec=90
TimeoutStopSec=30
KillMode=mixed
KillSignal=SIGTERM
User=root
Group=root
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
RuntimeDirectory=conflux
RuntimeDirectoryMode=0700
StateDirectory=conflux
StateDirectoryMode=0700
ConfigurationDirectory=conflux
ConfigurationDirectoryMode=0700
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`

type systemd struct{}

func newManager() (Manager, error) { return systemd{}, nil }

func (systemd) Name() string { return unitName }

func (s systemd) Install(exe string, args ...string) error {
	execStart := exe
	if len(args) > 0 {
		execStart = exe + " " + strings.Join(args, " ")
	}

	unit := fmt.Sprintf(unitTemplate, execStart)

	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil { //nolint:gosec // a unit file is world-readable by design
		return fmt.Errorf("write %s: %w", unitPath, err)
	}

	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}

	// Enable, and deliberately not start. Starting is the caller's decision, and
	// `conflux install` on a machine with no configuration must register without
	// starting anything.
	return run("systemctl", "enable", unitName)
}

func (s systemd) Remove() error {
	// Every step tolerates its own failure. The previous conflux returned on the
	// first error, so a unit file that had already been deleted made uninstall
	// impossible to complete.
	var first error

	note := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}

	note(run("systemctl", "disable", "--now", unitName))

	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		note(err)
	}

	note(run("systemctl", "daemon-reload"))
	_ = run("systemctl", "reset-failed", unitName)

	if installed, _ := s.Installed(); installed {
		return first
	}

	// It is gone, which is what was asked for, whatever complained on the way.
	return nil
}

func (systemd) Start() error   { return run("systemctl", "start", unitName) }
func (systemd) Stop() error    { return run("systemctl", "stop", unitName) }
func (systemd) Restart() error { return run("systemctl", "restart", unitName) }

// Installed is a stat rather than `systemctl list-unit-files`: cheaper, and it
// answers correctly on a machine where systemd is not currently running.
func (systemd) Installed() (bool, error) {
	_, err := os.Stat(unitPath)
	if err == nil {
		return true, nil
	}

	if os.IsNotExist(err) {
		return false, nil
	}

	return false, err
}

func (systemd) Running() (bool, error) {
	_, ok := query("systemctl", "is-active", "--quiet", unitName)

	return ok, nil
}

func (s systemd) Describe() string {
	installed, _ := s.Installed()
	if !installed {
		return "not installed"
	}

	state, _ := query("systemctl", "is-active", unitName)
	enabled, _ := query("systemctl", "is-enabled", unitName)

	if state == "" {
		state = "unknown"
	}

	if enabled == "" {
		enabled = "unknown"
	}

	return fmt.Sprintf("%s (systemd: %s, %s at boot)", state, unitName, enabled)
}
