//go:build windows
// +build windows

package service

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/veil-net/conflux/api"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type service struct {
	api *api.API
}

func newService() *service {
	api := api.NewAPI()
	return &service{
		api: api,
	}
}

func (s *service) Run() error {
	// Check if the conflux is running as a Windows service
	isWindowsService, err := svc.IsWindowsService()
	if err != nil {
		Logger.Sugar().Errorf("failed to check if running as a Windows service: %v", err)
		return err
	}

	// If the conflux is running as a Windows service, run as a Windows service
	if isWindowsService {
		svc.Run("VeilNet Conflux", s)
		return nil
	}

	// Create the context
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Run the API
	s.api.Run()

	// Wait for the context to be done
	<-ctx.Done()

	// Stop the API
	s.api.Stop()

	return nil
}

func (s *service) Install() error {

	// Get the executable path
	exe, err := os.Executable()
	if err != nil {
		Logger.Sugar().Errorf("failed to get executable path: %v", err)
		return err
	}

	// Connect to the service manager
	m, err := mgr.Connect()
	if err != nil {
		Logger.Sugar().Errorf("failed to connect to service manager: %v", err)
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
	service, err := m.CreateService("VeilNet Conflux", exe, cfg)
	if err != nil {
		Logger.Sugar().Errorf("failed to create service: %v", err)
		return err
	}
	defer service.Close()

	err = service.Start()
	if err != nil {
		Logger.Sugar().Errorf("failed to start service: %v", err)
		return err
	}
	Logger.Sugar().Infof("VeilNet Conflux service installed and started")
	return nil
}

func (s *service) Start() error {
	// Connect to the service manager
	m, err := mgr.Connect()
	if err != nil {
		Logger.Sugar().Errorf("failed to connect to service manager: %v", err)
		return err
	}
	defer m.Disconnect()

	// Open the service
	service, err := m.OpenService("VeilNet Conflux")
	if err != nil {
		Logger.Sugar().Errorf("failed to open service: %v", err)
		return err
	}
	defer service.Close()

	// Start the service
	err = service.Start()
	if err != nil {
		Logger.Sugar().Errorf("failed to start service: %v", err)
		return err
	}

	Logger.Sugar().Infof("VeilNet Conflux service started successfully")
	return nil
}

func (s *service) Stop() error {
	// Connect to the service manager
	m, err := mgr.Connect()
	if err != nil {
		Logger.Sugar().Errorf("failed to connect to service manager: %v", err)
		return err
	}
	defer m.Disconnect()

	// Open the service
	service, err := m.OpenService("VeilNet Conflux")
	if err != nil {
		Logger.Sugar().Errorf("failed to open service: %v", err)
		return err
	}
	defer service.Close()

	// Stop the service
	_, err = service.Control(svc.Stop)
	if err != nil {
		Logger.Sugar().Errorf("failed to stop service: %v", err)
		return err
	}

	Logger.Sugar().Infof("VeilNet Conflux service stopped successfully")
	return nil
}

func (s *service) Remove() error {
	// Connect to the service manager
	m, err := mgr.Connect()
	if err != nil {
		Logger.Sugar().Errorf("failed to connect to service manager: %v", err)
		return err
	}
	defer m.Disconnect()

	// Open the service
	service, err := m.OpenService("VeilNet Conflux")
	if err != nil {
		Logger.Sugar().Errorf("failed to open service: %v", err)
		return err
	}
	defer service.Close()

	// Stop the service first
	status, err := service.Control(svc.Stop)
	if err != nil {
		Logger.Sugar().Warnf("Failed to stop veilnet service: %v, status: %v", err, status)
	} else {
		Logger.Sugar().Infof("VeilNet Conflux service stopped")
	}

	// Delete the service
	err = service.Delete()
	if err != nil {
		Logger.Sugar().Errorf("failed to delete service: %v", err)
		return err
	}

	Logger.Sugar().Infof("VeilNet Conflux service removed successfully")
	return nil
}

func (s *service) Status() error {
	// Connect to the service manager
	m, err := mgr.Connect()
	if err != nil {
		Logger.Sugar().Errorf("failed to connect to service manager: %v", err)
		return err	
	}
	defer m.Disconnect()

	// Open the service
	service, err := m.OpenService("VeilNet Conflux")
	if err != nil {
		Logger.Sugar().Errorf("failed to open service: %v", err)
		return err
	}
	defer service.Close()

	// Get the service status
	status, err := service.Query()
	if err != nil {
		Logger.Sugar().Errorf("failed to query service: %v", err)
		return err
	}
	if status.State != svc.Running {
		Logger.Sugar().Errorf("VeilNet Conflux service is not running")
		return err
	}

	Logger.Sugar().Infof("VeilNet Conflux service status: %v", status)
	return nil
}

func (s *service) Execute(args []string, changeRequests <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {

	// Signal the service is starting
	changes <- svc.Status{State: svc.StartPending}

	// Run the API
	s.api.Run()

	// Set the status to running
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	// Monitor for service control requests and anchor context
	for changeRequest := range changeRequests {
		switch changeRequest.Cmd {
		case svc.Interrogate:
			changes <- changeRequest.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			s.api.Stop()
			changes <- svc.Status{State: svc.Stopped}
			return false, 0
		default:
			Logger.Sugar().Warnf("unexpected service control request: %v", changeRequest.Cmd)
			changes <- changeRequest.CurrentStatus
		}
	}
	return false, 0
}
