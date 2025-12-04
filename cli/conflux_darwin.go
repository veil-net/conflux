//go:build darwin
// +build darwin

package cli

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"text/template"
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
	// Check if conflux token is provided
	up := Up{}
	up.loadUpData()

	if up.Token != "" {

		if up.Portal {
			veilnet.Logger.Sugar().Errorf("Portal mode is not supported on macOS")
			return fmt.Errorf("portal mode is not supported on macOS")
		}

		if up.Guardian == "" {
			up.Guardian = "https://guardian.veilnet.app"
		}
		if up.Veil == "" {
			up.Veil = "nats.veilnet.app"
		}
		if up.VeilPort == 0 {
			up.VeilPort = 30422
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		// Start the anchor
		c.anchor = veilnet.NewAnchor()
		err := c.anchor.Start(up.Guardian, up.Veil, up.VeilPort, up.Token, false)
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to start VeilNet: %v", err)
			return err
		}

		// Link the anchor to the TUN device
		err = c.anchor.LinkWithTUN("utun", 1500)
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to link anchor to TUN device: %v", err)
			return err
		}

		// Start the metrics server
		c.metricsServer = &http.Server{
			Addr:    ":9090",
			Handler: c.anchor.Metrics.GetHandler(),
		}
		go func() {
			if err := c.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				veilnet.Logger.Sugar().Errorf("metrics server error: %v", err)
			}
		}()

		select {
		case <-ctx.Done():
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if c.metricsServer != nil {
				if err := c.metricsServer.Shutdown(ctx); err != nil {
					veilnet.Logger.Sugar().Errorf("failed to stop metrics server: %v", err)
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
					veilnet.Logger.Sugar().Errorf("failed to stop metrics server: %v", err)
				}
			}
			if c.anchor != nil {
				c.anchor.Stop()
			}
			return nil
		}
	} else {

		veilnet.Logger.Sugar().Warnf("Conflux token is not provided, will attempt to register")
		// If conflux token is not provided, load existing registration data
		register := Register{}
		register.loadRegistrationData()

		if register.Token == "" {
			veilnet.Logger.Sugar().Errorf("Token is missing in the registration data")
			return fmt.Errorf("token is missing in the registration data")
		}
		if register.Portal {
			veilnet.Logger.Sugar().Warnf("Portal mode is not supported on macOS")
			register.Portal = false
		}
		if register.Guardian == "" {
			register.Guardian = "https://guardian.veilnet.app"
		}
		if register.Veil == "" {
			register.Veil = "nats.veilnet.app"
		}
		if register.VeilPort == 0 {
			register.VeilPort = 30422
		}

		// Register the conflux
		confluxToken, err := register.register()
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to register conflux: %v", err)
			return err
		}

		// Save the registration data
		err = register.saveRegistrationData(confluxToken)
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to save registration data: %v", err)
			return err
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		// Start the anchor
		c.anchor = veilnet.NewAnchor()
		err = c.anchor.Start(register.Guardian, register.Veil, register.VeilPort, confluxToken.Token, false)
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to start VeilNet: %v", err)
			return err
		}

		// Link the anchor to the TUN device
		err = c.anchor.LinkWithTUN("utun", 1500)
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to link anchor to TUN device: %v", err)
			return err
		}

		// Start the metrics server
		c.metricsServer = &http.Server{
			Addr:    ":9090",
			Handler: c.anchor.Metrics.GetHandler(),
		}
		go func() {
			if err := c.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				veilnet.Logger.Sugar().Errorf("metrics server error: %v", err)
			}
		}()

		select {
		case <-ctx.Done():
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if c.metricsServer != nil {
				if err := c.metricsServer.Shutdown(ctx); err != nil {
					veilnet.Logger.Sugar().Errorf("failed to stop metrics server: %v", err)
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
					veilnet.Logger.Sugar().Errorf("failed to stop metrics server: %v", err)
				}
			}
			if c.anchor != nil {
				c.anchor.Stop()
			}
			return nil
		}
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

	// Start the service
	cmd := exec.Command("launchctl", "bootstrap", "system", plistFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to bootstrap launchctl service: %v: %s", err, string(out))
	}

	veilnet.Logger.Sugar().Infof("VeilNet Conflux service installed and started")
	return nil
}

func (c *conflux) Start() error {
	plistFile := "/Library/LaunchDaemons/org.veilnet.conflux.plist"
	cmd := exec.Command("launchctl", "bootstrap", "system", plistFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start launchctl service: %v: %s", err, string(out))
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service started")
	return nil
}

func (c *conflux) Stop() error {
	plistFile := "/Library/LaunchDaemons/org.veilnet.conflux.plist"
	cmd := exec.Command("launchctl", "bootout", "system", plistFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop launchctl service: %v: %s", err, string(out))
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service stopped")
	return nil
}

func (c *conflux) Remove() error {
	plistFile := "/Library/LaunchDaemons/org.veilnet.conflux.plist"
	cmd := exec.Command("launchctl", "bootout", "system", plistFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Warnf("Failed to stop launchctl service: %v: %s", err, string(out))
	} else {
		veilnet.Logger.Sugar().Infof("VeilNet Conflux service stopped")
	}

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
		return false, fmt.Errorf("VeilNet Conflux service is not running: %v: %s", err, string(out))
	}
	return true, nil
}
