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
	"path/filepath"
	"sync"
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
	api           *API
	metricsServer *http.Server

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
	tmpl, err := template.New("launchdaemon").Parse(LaunchDaemonPlistTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, struct{ ExecPath string }{ExecPath: realPath}); err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
	}

	// Write plist file
	plistFile := "/Library/LaunchDaemons/org.veilnet.conflux.plist"
	if err := os.WriteFile(plistFile, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write plist file: %v", err)
	}

	// Load the service
	cmd := exec.Command("launchctl", "load", plistFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to load service: %s", string(out))
		return fmt.Errorf("failed to load service: %v", err)
	}

	// Start the service
	cmd = exec.Command("launchctl", "start", "org.veilnet.conflux")
	out, err = cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to start service: %s", string(out))
		return fmt.Errorf("failed to start service: %v", err)
	}

	veilnet.Logger.Sugar().Infof("VeilNet Conflux service installed and started")
	return nil
}

func (c *conflux) Start() error {
	cmd := exec.Command("launchctl", "start", "org.veilnet.conflux")
	out, err := cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to start service: %s", string(out))
		return fmt.Errorf("failed to start service: %v", err)
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service started")
	return nil
}

func (c *conflux) Stop() error {
	cmd := exec.Command("launchctl", "stop", "org.veilnet.conflux")
	out, err := cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to stop service: %s", string(out))
		return fmt.Errorf("failed to stop service: %v", err)
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service stopped")
	return nil
}

func (c *conflux) Remove() error {
	cmd := exec.Command("launchctl", "stop", "org.veilnet.conflux")
	out, err := cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to stop service: %s", string(out))
		return err
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service stopped")

	plistFile := "/Library/LaunchDaemons/org.veilnet.conflux.plist"
	cmd = exec.Command("launchctl", "unload", plistFile)
	out, err = cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to unload service: %s", string(out))
		return fmt.Errorf("failed to unload service: %v", err)
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service unloaded")

	err = os.Remove(plistFile)
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to remove plist file: %v", err)
		return fmt.Errorf("failed to remove plist file: %v", err)
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
	err := c.anchor.Start(apiBaseURL, anchorToken, false)
	if err != nil {
		return err
	}

	// Link the anchor to the TUN device
	err = c.anchor.LinkWithTUN("veilnet", 1500)
	if err != nil {
		return err
	}

	// Close existing metrics server
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
