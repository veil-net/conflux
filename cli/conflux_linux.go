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
	"path/filepath"
	"sync"
	"time"

	"github.com/veil-net/veilnet"
)

const SystemdUnitTemplate = `[Unit]
Description=VeilNet Service
After=network.target

[Service]
Type=simple
ExecStart={{.ExecPath}}
ExecStop=/bin/kill -TERM $MAINPID
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
	anchor           *veilnet.Anchor
	api              *API
	metricsServer    *http.Server

	anchorMutex sync.Mutex
	anchorOnce  sync.Once
}

func newConflux() *conflux {
	c := &conflux{}
	c.api = newAPI(c)
	return c
}

func (c *conflux) Run() error {
	return c.api.Run()
}

func (c *conflux) Install() error {
	// Get current executable path
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	// Resolve symlinks to get real path
	realPath, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		realPath = exePath
	}

	// Parse and execute template
	tmpl, err := template.New("systemd").Parse(SystemdUnitTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, struct{ ExecPath string }{ExecPath: realPath}); err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
	}

	// Write unit file
	unitFile := "/etc/systemd/system/veilnet.service"
	if err := os.WriteFile(unitFile, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write unit file: %v", err)
	}

	// Reload systemd and enable service
	cmd := exec.Command("systemctl", "daemon-reload")
	out, err := cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to reload systemd: %s", string(out))
		return fmt.Errorf("failed to reload systemd: %v", err)
	}

	cmd = exec.Command("systemctl", "enable", "veilnet.service")
	out, err = cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to enable service: %s", string(out))
		return fmt.Errorf("failed to enable service: %v", err)
	}

	cmd = exec.Command("systemctl", "start", "veilnet.service")
	out, err = cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to start service: %s", string(out))
		return fmt.Errorf("failed to start service: %v", err)
	}

	veilnet.Logger.Sugar().Infof("VeilNet Conflux service installed and started")
	return nil
}

func (c *conflux) Start() error {
	cmd := exec.Command("systemctl", "start", "veilnet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to start service: %s", string(out))
		return fmt.Errorf("failed to start service: %v", err)
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service started")
	return nil
}

func (c *conflux) Stop() error {
	cmd := exec.Command("systemctl", "stop", "veilnet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to stop service: %s", string(out))
		return fmt.Errorf("failed to stop service: %v", err)
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service stopped")
	return nil
}

func (c *conflux) Remove() error {
	cmd := exec.Command("systemctl", "stop", "veilnet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to stop service: %s", string(out))
		return err
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service stopped")

	cmd = exec.Command("systemctl", "disable", "veilnet")
	out, err = cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to disable service: %s", string(out))
		return fmt.Errorf("failed to disable service: %v", err)
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service disabled")

	unitFile := "/etc/systemd/system/veilnet.service"
	err = os.Remove(unitFile)
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to remove unit file: %v", err)
		return fmt.Errorf("failed to remove unit file: %v", err)
	}

	// Reload systemd and enable service
	cmd = exec.Command("systemctl", "daemon-reload")
	out, err = cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to reload systemd: %s", string(out))
		return fmt.Errorf("failed to reload systemd: %v", err)
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service removed")

	return nil
}

func (c *conflux) Status() (bool, error) {

	// Check if the service is running
	cmd := exec.Command("systemctl", "is-active", "veilnet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("VeilNet Conflux service is not running: %v", string(out))
	}
	return true, nil
}

func (c *conflux) StartVeilNet(apiBaseURL, anchorToken string, portal bool) error {

	// Lock the anchor mutex
	c.anchorMutex.Lock()
	defer c.anchorMutex.Unlock()

	// initialize the anchor once
	c.anchorOnce = sync.Once{}

	//Close existing anchor if any (defensive cleanup)
	if c.anchor != nil {
		c.anchor.Stop()
		c.anchor = nil
	}

	// Create the anchor
	c.anchor = veilnet.NewAnchor()
	err := c.anchor.Start(apiBaseURL, anchorToken, portal)
	if err != nil {
		return err
	}

	// Start the TUN interface
	err = c.anchor.LinkWithTUN("veilnet", 1500)
	if err != nil {
		return err
	}

	// Close existing metrics server
	veilnet.Logger.Sugar().Infof("Starting metrics server")
	if c.metricsServer != nil {
		c.metricsServer.Shutdown(context.Background())
		c.metricsServer = nil
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
	veilnet.Logger.Sugar().Infof("Metrics server started")
	return nil
}

func (c *conflux) StopVeilNet() {

	c.anchorOnce.Do(func() {

		// Lock the anchor mutex
		c.anchorMutex.Lock()
		defer c.anchorMutex.Unlock()

		// Stop the metrics server
		if c.metricsServer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := c.metricsServer.Shutdown(ctx); err != nil {
				veilnet.Logger.Sugar().Errorf("failed to stop metrics server: %v", err)
			}
			c.metricsServer = nil
		}

		// Stop the anchor
		if c.anchor != nil {
			c.anchor.Stop()
			c.anchor = nil
		}
	})
}

func (c *conflux) GetAnchor() *veilnet.Anchor {
	if c.anchor == nil {
		return nil
	}
	return c.anchor
}