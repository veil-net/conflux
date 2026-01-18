//go:build linux
// +build linux

package service

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
)

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

type service struct {
	serviceImpl *ServiceImpl
}

func newService() *service {
	serviceImpl := NewServiceImpl()
	return &service{
		serviceImpl: serviceImpl,
	}
}

func (s *service) Run() error {

	// Run the API
	s.serviceImpl.Run()

	return nil
}

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
	cmd := exec.Command("systemctl", "daemon-reload")
	out, err := cmd.CombinedOutput()
	if err != nil {
		Logger.Sugar().Errorf("failed to reload systemd daemon: %v: %s", err, string(out))
		return err
	}

	cmd = exec.Command("systemctl", "enable", "veilnet.service")
	out, err = cmd.CombinedOutput()
	if err != nil {
		Logger.Sugar().Errorf("failed to enable veilnet service: %v: %s", err, string(out))
		return err
	}

	cmd = exec.Command("systemctl", "start", "veilnet.service")
	out, err = cmd.CombinedOutput()
	if err != nil {
		Logger.Sugar().Errorf("failed to start veilnet service: %v: %s", err, string(out))
		return err
	}

	Logger.Sugar().Infof("VeilNet Conflux service installed and started")
	return nil
}

func (s *service) Start() error {
	cmd := exec.Command("systemctl", "start", "veilnet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		Logger.Sugar().Errorf("failed to start veilnet service: %v: %s", err, string(out))
		return err
	}
	Logger.Sugar().Infof("VeilNet Conflux service started")
	return nil
}

func (s *service) Stop() error {
	cmd := exec.Command("systemctl", "stop", "veilnet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		Logger.Sugar().Errorf("failed to stop veilnet service: %v: %s", err, string(out))
		return err
	}
	Logger.Sugar().Infof("VeilNet Conflux service stopped")
	return nil
}

func (s *service) Remove() error {
	cmd := exec.Command("systemctl", "stop", "veilnet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		Logger.Sugar().Warnf("Failed to stop veilnet service: %v: %s", err, string(out))
	} else {
		Logger.Sugar().Infof("VeilNet Conflux service stopped")
	}

	cmd = exec.Command("systemctl", "disable", "veilnet")
	out, err = cmd.CombinedOutput()
	if err != nil {
		Logger.Sugar().Errorf("failed to disable veilnet service: %v: %s", err, string(out))
		return err
	}
	Logger.Sugar().Infof("VeilNet Conflux service disabled")

	unitFile := "/etc/systemd/system/veilnet.service"
	err = os.Remove(unitFile)
	if err != nil {
		Logger.Sugar().Errorf("Failed to remove unit file: %v", err)
		return err
	}

	// Reload systemd and enable service
	cmd = exec.Command("systemctl", "daemon-reload")
	out, err = cmd.CombinedOutput()
	if err != nil {
		Logger.Sugar().Errorf("failed to reload systemd daemon: %v: %s", err, string(out))
		return err
	}
	Logger.Sugar().Infof("VeilNet Conflux service removed")
	return nil
}

func (s *service) Status() error {
	// Check if the service is running
	cmd := exec.Command("systemctl", "is-active", "veilnet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		Logger.Sugar().Errorf("VeilNet Conflux service status: %s", string(out))
		return err
	}
	Logger.Sugar().Infof("VeilNet Conflux service status: %s", string(out))
	return nil
}
