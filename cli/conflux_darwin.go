//go:build darwin
// +build darwin

package cli

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/veil-net/veilnet"
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

type conflux struct {
	anchor        *veilnet.Anchor
	metricsServer *http.Server
}

func newConflux() *conflux {
	c := &conflux{}
	return c
}

func (c *conflux) Run() error {
	// Load existing registration data
	register := Register{}
	register.loadRegistrationData()

	if register.Guardian == "" {
		veilnet.Logger.Sugar().Errorf("Guardian URL is missing in the registration data")
		return fmt.Errorf("guardian URL is missing in the registration data")
	}
	if register.Token == "" {
		veilnet.Logger.Sugar().Errorf("Token is missing in the registration data")
		return fmt.Errorf("token is missing in the registration data")
	}
	if register.Portal {
		veilnet.Logger.Sugar().Errorf("Portal mode is not supported on macOS")
		return fmt.Errorf("portal mode is not supported on macOS")
	}

	// Register the conflux
	confluxToken, err := register.register()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("Failed to register conflux: %v", err)
		return err
	}

	// Save the registration data
	err = register.saveRegistrationData(confluxToken)
	if err != nil {
		veilnet.Logger.Sugar().Errorf("Failed to save registration data: %v", err)
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start the anchor
	c.anchor = veilnet.NewAnchor()
	err = c.anchor.Start(register.Guardian, confluxToken.Token, false)
	if err != nil {
		veilnet.Logger.Sugar().Errorf("Failed to start VeilNet: %v", err)
		return err
	}

	// Link the anchor to the TUN device
	err = c.anchor.LinkWithTUN("veilnet", 1500)
	if err != nil {
		veilnet.Logger.Sugar().Errorf("Failed to link anchor to TUN device: %v", err)
		return err
	}

	// Start the metrics server
	c.metricsServer = &http.Server{
		Addr:    ":9090",
		Handler: c.anchor.Metrics.GetHandler(),
	}
	go func() {
		if err := c.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			veilnet.Logger.Sugar().Errorf("Metrics server error: %v", err)
		}
	}()

	select {
	case <-ctx.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if c.metricsServer != nil {
			if err := c.metricsServer.Shutdown(ctx); err != nil {
				veilnet.Logger.Sugar().Errorf("Failed to stop metrics server: %v", err)
			}
		}
		if c.anchor != nil {
			c.anchor.Stop()
		}
		return nil
	case <-c.anchor.Ctx.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if c.metricsServer != nil {
			if err := c.metricsServer.Shutdown(ctx); err != nil {
				veilnet.Logger.Sugar().Errorf("Failed to stop metrics server: %v", err)
			}
		}
		return nil
	}
}

func (c *conflux) Install() error {
	// Get current executable path
	exePath, err := os.Executable()
	if err != nil {
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
		return err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, struct{ ExecPath string }{ExecPath: realPath}); err != nil {
		return err
	}

	// Write plist file
	plistFile := "/Library/LaunchDaemons/org.veilnet.conflux.plist"
	if err := os.WriteFile(plistFile, buf.Bytes(), 0644); err != nil {
		return err
	}

	// Load the service
	cmd := exec.Command("launchctl", "load", plistFile)
	_, err = cmd.CombinedOutput()
	if err != nil {
		return err
	}

	// Start the service
	cmd = exec.Command("launchctl", "start", "org.veilnet.conflux")
	_, err = cmd.CombinedOutput()
	if err != nil {
		return err
	}

	veilnet.Logger.Sugar().Infof("VeilNet Conflux service installed and started")
	return nil
}

func (c *conflux) Start() error {
	cmd := exec.Command("launchctl", "start", "org.veilnet.conflux")
	_, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service started")
	return nil
}

func (c *conflux) Stop() error {
	cmd := exec.Command("launchctl", "stop", "org.veilnet.conflux")
	_, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service stopped")
	return nil
}

func (c *conflux) Remove() error {
	cmd := exec.Command("launchctl", "stop", "org.veilnet.conflux")
	_, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service stopped")

	plistFile := "/Library/LaunchDaemons/org.veilnet.conflux.plist"
	cmd = exec.Command("launchctl", "unload", plistFile)
	_, err = cmd.CombinedOutput()
	if err != nil {
		return err
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service unloaded")

	err = os.Remove(plistFile)
	if err != nil {
		return err
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service removed")

	return nil
}

func (c *conflux) Status() (bool, error) {
	// Check if the service is running
	cmd := exec.Command("launchctl", "list", "org.veilnet.conflux")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("VeilNet Conflux service is not running: %v", string(out))
	}
	return true, nil
}
