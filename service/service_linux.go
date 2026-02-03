//go:build linux
// +build linux

package service

import (
	"bytes"
	"os"
	"path/filepath"
	"text/template"
)

// SystemdUnitTemplate is the systemd unit file template for the conflux service.
const SystemdUnitTemplate = `[Unit]
Description=VeilNet Service
After=network.target
Wants=network.target
Before=multi-user.target

[Service]
Type=simple
ExecStart={{.ExecPath}}
Restart=always
RestartSec=5
User=root
Group=root
TimeoutStopSec=30
KillMode=mixed
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
`

// service is the Linux implementation holding the ServiceImpl.
type service struct {
	serviceImpl *ServiceImpl
}

// newService returns the Linux-specific service.
func newService() *service {
	serviceImpl := NewServiceImpl()
	return &service{
		serviceImpl: serviceImpl,
	}
}

// Run delegates to the service implementation (runs the anchor in the foreground).
//
// Inputs:
//   - s: *service. Wraps the ServiceImpl.
//
// Outputs:
//   - err: error. Non-nil if delegation fails.
func (s *service) Run() error {

	// Run the API
	s.serviceImpl.Run()

	return nil
}

// Install installs and starts the conflux service via systemd.
//
// Inputs:
//   - s: *service. The Linux service.
//
// Outputs:
//   - err: error. Non-nil if the template, file write, or system command fails.
func (s *service) Install() error {
	// Get current executable path
	exePath, err := os.Executable()
	if err != nil {
		Logger.Sugar().Errorf("failed to get executable path: %v", err)
		return err
	}

	// Resolve symlinks to get real path
	realPath, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		realPath = exePath
	}

	// Parse and execute template
	tmpl, err := template.New("systemd").Parse(SystemdUnitTemplate)
	if err != nil {
		Logger.Sugar().Errorf("failed to parse systemd template: %v", err)
		return err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, struct{ ExecPath string }{ExecPath: realPath}); err != nil {
		Logger.Sugar().Errorf("failed to execute systemd template: %v", err)
		return err
	}

	// Write unit file
	unitFile := "/etc/systemd/system/veilnet.service"
	if err := os.WriteFile(unitFile, buf.Bytes(), 0644); err != nil {
		Logger.Sugar().Errorf("failed to write systemd unit file: %v", err)
		return err
	}

	// Reload systemd and enable service
	err = ExecuteCmd("systemctl", "daemon-reload")
	if err != nil {
		return err
	}

	err = ExecuteCmd("systemctl", "enable", "veilnet.service")
	if err != nil {
		return err
	}

	err = ExecuteCmd("systemctl", "start", "veilnet.service")
	if err != nil {
		return err
	}

	Logger.Sugar().Infof("VeilNet Conflux service installed and started")
	return nil
}

// Start starts the conflux service via systemctl.
//
// Inputs:
//   - s: *service. The Linux service.
//
// Outputs:
//   - err: error. Non-nil if the system command fails.
func (s *service) Start() error {
	err := ExecuteCmd("systemctl", "start", "veilnet")
	if err != nil {
		return err
	}
	Logger.Sugar().Infof("VeilNet Conflux service started")
	return nil
}

// Stop stops the conflux service via systemctl.
//
// Inputs:
//   - s: *service. The Linux service.
//
// Outputs:
//   - err: error. Non-nil if the system command fails.
func (s *service) Stop() error {
	err := ExecuteCmd("systemctl", "stop", "veilnet")
	if err != nil {
		return err
	}
	Logger.Sugar().Infof("VeilNet Conflux service stopped")
	return nil
}

// Remove stops, disables, and removes the systemd unit file; then reloads systemd.
//
// Inputs:
//   - s: *service. The Linux service.
//
// Outputs:
//   - err: error. Non-nil if a step fails.
func (s *service) Remove() error {
	err := ExecuteCmd("systemctl", "stop", "veilnet")
	if err != nil {
		return err
	}

	err = ExecuteCmd("systemctl", "disable", "veilnet")
	if err != nil {
		return err
	}

	unitFile := "/etc/systemd/system/veilnet.service"
	err = os.Remove(unitFile)
	if err != nil {
		Logger.Sugar().Errorf("Failed to remove unit file: %v", err)
		return err
	}

	// Reload systemd and enable service
	err = ExecuteCmd("systemctl", "daemon-reload")
	if err != nil {
		return err
	}
	Logger.Sugar().Infof("VeilNet Conflux service uninstalled")
	return nil
}

// Status reports the conflux service status via systemctl.
//
// Inputs:
//   - s: *service. The Linux service.
//
// Outputs:
//   - err: error. Non-nil if the system command fails.
func (s *service) Status() error {
	// Check if the service is running
	err := ExecuteCmd("systemctl", "status", "veilnet")
	if err != nil {
		return err
	}
	return nil
}
