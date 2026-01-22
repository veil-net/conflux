//go:build darwin
// +build darwin

package service

import (
	"bytes"
	"os"
	"path/filepath"
	"text/template"
)

const LaunchDaemonPlistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>org.veilnet.conflux</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{.ExecPath}}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>/var/log/veilnet-conflux.log</string>
	<key>StandardErrorPath</key>
	<string>/var/log/veilnet-conflux.error.log</string>
</dict>
</plist>
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
	tmpl, err := template.New("launchdaemon").Parse(LaunchDaemonPlistTemplate)
	if err != nil {
		Logger.Sugar().Errorf("failed to parse launchdaemon template: %v", err)
		return err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, struct{ ExecPath string }{ExecPath: realPath}); err != nil {
		Logger.Sugar().Errorf("failed to execute launchdaemon template: %v", err)
		return err
	}

	// Write plist file
	plistFile := "/Library/LaunchDaemons/org.veilnet.conflux.plist"
	if err := os.WriteFile(plistFile, buf.Bytes(), 0644); err != nil {
		Logger.Sugar().Errorf("failed to write launchdaemon plist file: %v", err)
		return err
	}

	// Start the service
	err = ExecuteCmd("launchctl", "bootstrap", "system", plistFile)
	if err != nil {
		return err
	}

	Logger.Sugar().Infof("VeilNet Conflux service installed and started")
	return nil
}

func (s *service) Start() error {
	plistFile := "/Library/LaunchDaemons/org.veilnet.conflux.plist"
	err := ExecuteCmd("launchctl", "bootstrap", "system", plistFile)
	if err != nil {
		return err
	}
	Logger.Sugar().Infof("VeilNet Conflux service started")
	return nil
}

func (s *service) Stop() error {
	plistFile := "/Library/LaunchDaemons/org.veilnet.conflux.plist"
	err := ExecuteCmd("launchctl", "bootout", "system", plistFile)
	if err != nil {
		return err
	}
	Logger.Sugar().Infof("VeilNet Conflux service stopped")
	return nil
}

func (s *service) Remove() error {
	plistFile := "/Library/LaunchDaemons/org.veilnet.conflux.plist"
	err := ExecuteCmd("launchctl", "bootout", "system", plistFile)
	if err != nil {
		return err
	}
	err = os.Remove(plistFile)
	if err != nil {
		Logger.Sugar().Errorf("failed to remove launchdaemon plist file: %v", err)
		return err
	}
	Logger.Sugar().Infof("VeilNet Conflux service uninstalled")
	return nil
}

func (s *service) Status() error {
	// Check if the service is running
	err := ExecuteCmd("launchctl", "list", "org.veilnet.conflux")
	if err != nil {
		return err
	}
	Logger.Sugar().Infof("VeilNet Conflux service status: running")
	return nil
}
