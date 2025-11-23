//go:build windows
// +build windows

package cli

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"encoding/json"

	"github.com/labstack/echo/v4"
	"github.com/veil-net/veilnet"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

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

	// Check if the conflux is running as a Windows service
	isWindowsService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}

	// If the conflux is running as a Windows service, run as a Windows service
	if isWindowsService {
		return svc.Run("veilnet", c)
	}

	// If the conflux is not running as a Windows service, run as a HTTP server
	return c.api.Run()
}

func (c *conflux) Install() error {

	// Get the executable path
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	// Connect to the service manager
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	// Create the service configuration
	cfg := mgr.Config{
		DisplayName:      "VeilNet Conflux",
		StartType:        mgr.StartAutomatic,
		Description:      "VeilNet Conflux service",
		ServiceStartName: "LocalSystem",
	}

	// Create the service
	s, err := m.CreateService("VeilNet Conflux", exe, cfg)
	if err != nil {
		return err
	}
	defer s.Close()

	err = s.Start()
	if err != nil {
		return fmt.Errorf("failed to start VeilNet Conflux service: %v", err)
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service installed and started")
	return nil
}

func (c *conflux) Start() error {
	// Connect to the service manager
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	// Open the service
	s, err := m.OpenService("VeilNet Conflux")
	if err != nil {
		return fmt.Errorf("failed to open VeilNet Conflux service: %v", err)
	}
	defer s.Close()

	// Start the service
	err = s.Start()
	if err != nil {
		return fmt.Errorf("failed to start VeilNet Conflux service: %v", err)
	}

	veilnet.Logger.Sugar().Info("VeilNet Conflux service started successfully")
	return nil
}

func (c *conflux) Stop() error {
	// Connect to the service manager
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	// Open the service
	s, err := m.OpenService("VeilNet Conflux")
	if err != nil {
		return fmt.Errorf("failed to open VeilNet Conflux service: %v", err)
	}
	defer s.Close()

	// Stop the service
	_, err = s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("failed to stop VeilNet Conflux service: %v", err)
	}

	veilnet.Logger.Sugar().Info("VeilNet Conflux service stopped successfully")
	return nil
}

func (c *conflux) Remove() error {
	// Connect to the service manager
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	// Open the service
	s, err := m.OpenService("VeilNet Conflux")
	if err != nil {
		return fmt.Errorf("failed to open VeilNet Conflux service: %v", err)
	}
	defer s.Close()

	// Stop the service first
	s.Control(svc.Stop)

	// Delete the service
	err = s.Delete()
	if err != nil {
		return fmt.Errorf("failed to delete VeilNet Conflux service: %v", err)
	}

	veilnet.Logger.Sugar().Info("VeilNet Conflux service removed successfully")
	return nil
}

func (c *conflux) Status() (bool, error) {
	// Connect to the service manager
	m, err := mgr.Connect()
	if err != nil {
		return false, fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	// Open the service
	s, err := m.OpenService("VeilNet Conflux")
	if err != nil {
		return false, fmt.Errorf("failed to open VeilNet Conflux service: %v", err)
	}
	defer s.Close()

	// Get the service status
	status, err := s.Query()
	if err != nil {
		return false, fmt.Errorf("failed to query VeilNet Conflux service: %v", err)
	}
	if status.State != svc.Running {
		return false, fmt.Errorf("VeilNet Conflux service is not running")
	}
	return true, nil
}

func (c *conflux) StartVeilNet(apiBaseURL, anchorToken string, portal bool) error {

	// Lock the anchor mutex
	c.anchorMutex.Lock()
	defer c.anchorMutex.Unlock()

	// initialize the anchor once
	c.anchorOnce = sync.Once{}

	//Close existing anchor
	if c.anchor != nil {
		c.anchor.Stop()
		c.anchor = nil
	}

	// Start the anchor
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

func (c *conflux) Execute(args []string, changeRequests <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	changes <- svc.Status{State: svc.StartPending}

	// Create the server
	c.api.server = echo.New()

	// Register routes
	c.api.server.POST("/up", c.api.up)
	c.api.server.POST("/down", c.api.down)
	c.api.server.POST("/register", c.api.register)
	c.api.server.POST("/unregister", c.api.unregister)
	// Start server
	go func() {
		if err := c.api.server.Start("127.0.0.1:1993"); err != nil && err != http.ErrServerClosed {
			c.StopVeilNet()
			veilnet.Logger.Sugar().Fatalf("Conflux service encountered an error: %v", err)
		}
	}()
	// Load existing registration data
	var register Register
	tmpDir, err := os.UserConfigDir()
	if err == nil {
		confluxDir := filepath.Join(tmpDir, "conflux")
		confluxFile := filepath.Join(confluxDir, "conflux.json")
		registrationDataFile, err := os.ReadFile(confluxFile)
		if err == nil {
			json.Unmarshal(registrationDataFile, &register)
		}
	} else {
		guardian := os.Getenv("VEILNET_GUARDIAN")
		token := os.Getenv("VEILNET_REGISTRATION_TOKEN")
		tag := os.Getenv("VEILNET_CONFLUX_TAG")
		cidr := os.Getenv("VEILNET_CONFLUX_CIDR")
		portal := os.Getenv("VEILNET_PORTAL") == "true"
		teams := os.Getenv("VEILNET_CONFLUX_TEAMS")
		register = Register{
			Tag:      tag,
			Cidr:     cidr,
			Guardian: guardian,
			Token:    token,
			Portal:   portal,
			Teams:    teams,
		}
	}
	if register.Guardian != "" || register.Token != "" {
		go func() {
			veilnet.Logger.Sugar().Infof("registering conflux from loaded registration data or environment variables")
			time.Sleep(1 * time.Second)
			err := register.Run()
			if err != nil {
				veilnet.Logger.Sugar().Errorf("failed to register conflux: %v", err)
			}
		}()
	}
	// Set the status to running
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for changeRequest := range changeRequests {
		switch changeRequest.Cmd {
		case svc.Interrogate:
			changes <- changeRequest.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := c.api.server.Shutdown(ctx); err != nil {
				veilnet.Logger.Sugar().Errorf("shutting down the server: %v", err)
				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			}
			// Stop the veilnet
			c.StopVeilNet()
			changes <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}

	return false, 0
}
