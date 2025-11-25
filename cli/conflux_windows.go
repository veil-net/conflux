//go:build windows
// +build windows

package cli

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/veil-net/veilnet"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type conflux struct {
	anchor        *veilnet.Anchor
	metricsServer *http.Server
}

func newConflux() *conflux {
	c := &conflux{}
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
		return svc.Run("VeilNet Conflux", c)
	}

	// Check if conflux token is provided
	up := Up{}
	up.loadUpData()

	if up.Token != "" && up.Guardian != "" {

		if up.Portal {
			veilnet.Logger.Sugar().Errorf("Portal mode is not supported on Windows")
			return fmt.Errorf("portal mode is not supported on Windows")
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		// Start the anchor
		c.anchor = veilnet.NewAnchor()
		err = c.anchor.Start(up.Guardian, up.Token, false)
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
		veilnet.Logger.Sugar().Warnf("Conflux token is not provided, will attempt to register")
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
		if register.Portal {
			veilnet.Logger.Sugar().Errorf("Portal mode is not supported on Windows")
			return fmt.Errorf("portal mode is not supported on Windows")
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
		err = c.anchor.Start(register.Guardian, confluxToken.Token, false)
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
		return err
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service installed and started")
	return nil
}

func (c *conflux) Start() error {
	// Connect to the service manager
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	// Open the service
	s, err := m.OpenService("VeilNet Conflux")
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	defer s.Close()

	// Start the service
	err = s.Start()
	if err != nil {
		return err
	}

	veilnet.Logger.Sugar().Info("VeilNet Conflux service started successfully")
	return nil
}

func (c *conflux) Stop() error {
	// Connect to the service manager
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	// Open the service
	s, err := m.OpenService("VeilNet Conflux")
	if err != nil {
		return err
	}
	defer s.Close()

	// Stop the service
	_, err = s.Control(svc.Stop)
	if err != nil {
		return err
	}

	veilnet.Logger.Sugar().Info("VeilNet Conflux service stopped successfully")
	return nil
}

func (c *conflux) Remove() error {
	// Connect to the service manager
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	// Open the service
	s, err := m.OpenService("VeilNet Conflux")
	if err != nil {
		return err
	}
	defer s.Close()

	// Stop the service first
	status, err := s.Control(svc.Stop)
	if err != nil {
		veilnet.Logger.Sugar().Warnf("Failed to stop veilnet service: %v, status: %v", err, status)
	} else {
		veilnet.Logger.Sugar().Infof("VeilNet Conflux service stopped")
	}


	// Delete the service
	err = s.Delete()
	if err != nil {
		return err
	}

	veilnet.Logger.Sugar().Info("VeilNet Conflux service removed successfully")
	return nil
}

func (c *conflux) Status() (bool, error) {
	// Connect to the service manager
	m, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer m.Disconnect()

	// Open the service
	s, err := m.OpenService("VeilNet Conflux")
	if err != nil {
		return false, err
	}
	defer s.Close()

	// Get the service status
	status, err := s.Query()
	if err != nil {
		return false, err
	}
	if status.State != svc.Running {
		return false, fmt.Errorf("VeilNet Conflux service is not running")
	}
	return true, nil
}

func (c *conflux) Execute(args []string, changeRequests <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {

	// Signal the service is starting
	changes <- svc.Status{State: svc.StartPending}

	// Check if conflux token is provided
	up := Up{}
	up.loadUpData()

	if up.Token != "" && up.Guardian != "" {

		if up.Portal {
			veilnet.Logger.Sugar().Errorf("Portal mode is not supported on Windows")
			return false, 1
		}

		// Start the anchor
		c.anchor = veilnet.NewAnchor()
		err := c.anchor.Start(up.Guardian, up.Token, false)
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to start VeilNet: %v", err)
			changes <- svc.Status{State: svc.Stopped}
			return false, 1
		}

		// Link the anchor to the TUN device
		err = c.anchor.LinkWithTUN("veilnet", 1500)
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to link anchor to TUN device: %v", err)
			changes <- svc.Status{State: svc.Stopped}
			return false, 1
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

		// Set the status to running
		changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

		// Monitor for service control requests and anchor context
		for {
			select {
			case changeRequest := <-changeRequests:
				switch changeRequest.Cmd {
				case svc.Interrogate:
					changes <- changeRequest.CurrentStatus
				case svc.Stop, svc.Shutdown:
					changes <- svc.Status{State: svc.StopPending}
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
					changes <- svc.Status{State: svc.Stopped}
					return false, 0
				default:
					veilnet.Logger.Sugar().Warnf("unexpected service control request: %v", changeRequest.Cmd)
					changes <- changeRequest.CurrentStatus
				}
			case <-c.anchor.Ctx.Done():
				// Anchor stopped unexpectedly, shutdown the service
				veilnet.Logger.Sugar().Errorf("anchor context done, shutting down service")
				changes <- svc.Status{State: svc.StopPending}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if c.metricsServer != nil {
					if err := c.metricsServer.Shutdown(ctx); err != nil {
						veilnet.Logger.Sugar().Errorf("failed to stop metrics server: %v", err)
					}
				}
				changes <- svc.Status{State: svc.Stopped}
				return false, 1
			}
		}
	} else {

		veilnet.Logger.Sugar().Warnf("Conflux token is not provided, will attempt to register")
		// Load existing registration data
		register := Register{}
		register.loadRegistrationData()

		if register.Guardian == "" {
			veilnet.Logger.Sugar().Errorf("Guardian URL is missing in the registration data")
			changes <- svc.Status{State: svc.Stopped}
			return false, 1
		}
		if register.Token == "" {
			veilnet.Logger.Sugar().Errorf("Token is missing in the registration data")
			changes <- svc.Status{State: svc.Stopped}
			return false, 1
		}
		if register.Portal {
			veilnet.Logger.Sugar().Errorf("Portal mode is not supported on Windows")
			changes <- svc.Status{State: svc.Stopped}
			return false, 1
		}

		// Register the conflux
		confluxToken, err := register.register()
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to register conflux: %v", err)
			changes <- svc.Status{State: svc.Stopped}
			return false, 1
		}

		// Save the registration data
		err = register.saveRegistrationData(confluxToken)
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to save registration data: %v", err)
			changes <- svc.Status{State: svc.Stopped}
			return false, 1
		}

		// Start the anchor
		c.anchor = veilnet.NewAnchor()
		err = c.anchor.Start(register.Guardian, confluxToken.Token, false)
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to start VeilNet: %v", err)
			changes <- svc.Status{State: svc.Stopped}
			return false, 1
		}

		// Link the anchor to the TUN device
		err = c.anchor.LinkWithTUN("veilnet", 1500)
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to link anchor to TUN device: %v", err)
			changes <- svc.Status{State: svc.Stopped}
			return false, 1
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

		// Set the status to running
		changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

		// Monitor for service control requests and anchor context
		for {
			select {
			case changeRequest := <-changeRequests:
				switch changeRequest.Cmd {
				case svc.Interrogate:
					changes <- changeRequest.CurrentStatus
				case svc.Stop, svc.Shutdown:
					changes <- svc.Status{State: svc.StopPending}
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
					changes <- svc.Status{State: svc.Stopped}
					return false, 0
				default:
					veilnet.Logger.Sugar().Warnf("unexpected service control request: %v", changeRequest.Cmd)
					changes <- changeRequest.CurrentStatus
				}
			case <-c.anchor.Ctx.Done():
				// Anchor stopped unexpectedly, shutdown the service
				veilnet.Logger.Sugar().Errorf("anchor context done, shutting down service")
				changes <- svc.Status{State: svc.StopPending}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if c.metricsServer != nil {
					if err := c.metricsServer.Shutdown(ctx); err != nil {
						veilnet.Logger.Sugar().Errorf("failed to stop metrics server: %v", err)
					}
				}
				changes <- svc.Status{State: svc.Stopped}
				return false, 1
			}
		}
	}
}
