//go:build linux
// +build linux

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

	if up.Token != "" && up.Guardian != "" {

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		// Start the anchor
		c.anchor = veilnet.NewAnchor()
		err := c.anchor.Start(up.Guardian, up.Token, up.Portal)
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to start VeilNet: %v", err)
			return err
		}

		// Link the anchor to the TUN device
		err = c.anchor.LinkWithTUN("veilnet", 1500)
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

		// If conflux token is not provided, load existing registration data
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
		// Portal mode is supported on Linux, so we use the value from registration

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
		err = c.anchor.Start(register.Guardian, confluxToken.Token, register.Portal)
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to start VeilNet: %v", err)
			return err
		}

		// Link the anchor to the TUN device
		err = c.anchor.LinkWithTUN("veilnet", 1500)
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
	tmpl, err := template.New("systemd").Parse(SystemdUnitTemplate)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, struct{ ExecPath string }{ExecPath: realPath}); err != nil {
		return err
	}

	// Write unit file
	unitFile := "/etc/systemd/system/veilnet.service"
	if err := os.WriteFile(unitFile, buf.Bytes(), 0644); err != nil {
		return err
	}

	// Reload systemd and enable service
	cmd := exec.Command("systemctl", "daemon-reload")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %v: %s", err, string(out))
	}

	cmd = exec.Command("systemctl", "enable", "veilnet.service")
	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to enable veilnet service: %v: %s", err, string(out))
	}

	cmd = exec.Command("systemctl", "start", "veilnet.service")
	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start veilnet service: %v: %s", err, string(out))
	}

	veilnet.Logger.Sugar().Infof("VeilNet Conflux service installed and started")
	return nil
}

func (c *conflux) Start() error {
	cmd := exec.Command("systemctl", "start", "veilnet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start veilnet service: %v: %s", err, string(out))
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service started")
	return nil
}

func (c *conflux) Stop() error {
	cmd := exec.Command("systemctl", "stop", "veilnet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop veilnet service: %v: %s", err, string(out))
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service stopped")
	return nil
}

func (c *conflux) Remove() error {
	cmd := exec.Command("systemctl", "stop", "veilnet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop veilnet service: %v: %s", err, string(out))
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service stopped")

	cmd = exec.Command("systemctl", "disable", "veilnet")
	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to disable veilnet service: %v: %s", err, string(out))
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service disabled")

	unitFile := "/etc/systemd/system/veilnet.service"
	err = os.Remove(unitFile)
	if err != nil {
		veilnet.Logger.Sugar().Errorf("Failed to remove unit file: %v", err)
		return err
	}

	// Reload systemd and enable service
	cmd = exec.Command("systemctl", "daemon-reload")
	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %v: %s", err, string(out))
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service removed")

	return nil
}

func (c *conflux) Status() (bool, error) {
	// Check if the service is running
	cmd := exec.Command("systemctl", "is-active", "veilnet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("VeilNet Conflux service is not running: %v: %s", err, string(out))
	}
	return true, nil
}
