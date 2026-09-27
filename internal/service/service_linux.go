//go:build linux

package service

import (
	"fmt"
	"os"
	"strings"
)

// unitName is used everywhere, suffix included: systemd appends .service to a bare
// name, and relying on that breaks the day a conflux.socket appears beside it.
//
// A function and not a constant because a run rooted in a CONFLUX_DIR is a separate
// installation and must not be registered over the machine's own; see scope.
func unitName() string { return "conflux" + scope() + ".service" }

func unitPath() string { return "/etc/systemd/system/" + unitName() }

// unitTemplate is the unit conflux writes.
//
// Type=notify, with sd_notify from the supervisor, is what makes `systemctl start`
// return only once the anchor is actually up rather than once fork succeeded.
//
// RestartPreventExitStatus=78 70 is the two answers a restart would only repeat.
// `conflux serve` exits 78 when there is nothing to start, and 70 when it has given up
// on a configuration or a host that no retry changes; without this the unit would
// restart into the same answer every five seconds forever, instead of showing failed.
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
RestartPreventExitStatus=78 70
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

func (s systemd) Install(exe string, args ...string) error {
	execStart := exe
	if len(args) > 0 {
		execStart = exe + " " + strings.Join(args, " ")
	}

	unit := fmt.Sprintf(unitTemplate, execStart)

	if err := os.WriteFile(unitPath(), []byte(unit), 0o644); err != nil { //nolint:gosec // a unit file is world-readable by design
		return fmt.Errorf("write %s: %w", unitPath(), err)
	}

	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}

	// Enable, and deliberately not start. Starting is the caller's decision, and
	// `conflux install` on a machine with no configuration must register without
	// starting anything.
	return run("systemctl", "enable", unitName())
}

func (s systemd) Remove() error {
	// Every step tolerates its own failure, so a unit file already deleted does not
	// stop the rest from being undone.
	var first error

	note := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}

	note(run("systemctl", "disable", "--now", unitName()))

	if err := os.Remove(unitPath()); err != nil && !os.IsNotExist(err) {
		note(err)
	}

	note(run("systemctl", "daemon-reload"))
	_ = run("systemctl", "reset-failed", unitName())

	if installed, _ := s.Installed(); installed {
		return first
	}

	// It is gone, which is what was asked for, whatever complained on the way.
	return nil
}

func (systemd) Stop() error    { return run("systemctl", "stop", unitName()) }
func (systemd) Restart() error { return run("systemctl", "restart", unitName()) }

// Installed is a stat rather than `systemctl list-unit-files`: cheaper, and it
// answers correctly on a machine where systemd is not currently running.
func (systemd) Installed() (bool, error) {
	_, err := os.Stat(unitPath())
	if err == nil {
		return true, nil
	}

	if os.IsNotExist(err) {
		return false, nil
	}

	return false, err
}

// Describe asks systemd once for both answers it gives.
func (s systemd) Describe() string {
	installed, _ := s.Installed()
	if !installed {
		return "not installed"
	}

	out, _ := query("systemctl", "show", unitName(), "--property=ActiveState,UnitFileState")

	state, enabled := "unknown", "unknown"

	for line := range strings.Lines(out) {
		key, value, _ := strings.Cut(strings.TrimSpace(line), "=")

		switch {
		case value == "":
		case key == "ActiveState":
			state = value
		case key == "UnitFileState":
			enabled = value
		}
	}

	return fmt.Sprintf("%s (systemd: %s, %s at boot)", state, unitName(), enabled)
}

func (systemd) LogHint() string { return "journalctl -u " + unitName() + " -n 50" }
