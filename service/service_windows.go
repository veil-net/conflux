//go:build windows
// +build windows

package service

import (
	"context"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"github.com/veil-net/conflux/anchor"
	pb "github.com/veil-net/conflux/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// service is the Windows implementation holding the ServiceImpl; it implements svc.Handler via Execute.
type service struct {
	serviceImpl *ServiceImpl
}

// newService returns the Windows-specific service.
func newService() *service {
	serviceImpl := NewServiceImpl()
	return &service{
		serviceImpl: serviceImpl,
	}
}

// Run either runs as a Windows SCM service (if already a service) or delegates to the service implementation.
//
// Inputs:
//   - s: *service. Wraps the ServiceImpl.
//
// Outputs:
//   - err: error. Non-nil if delegation or svc.Run fails.
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

	// Run the API
	s.serviceImpl.Run()

	return nil
}

// Install creates and starts the conflux service in the Windows SCM.
//
// Inputs:
//   - s: *service. The Windows service.
//
// Outputs:
//   - err: error. Non-nil if the SCM call fails.
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

// Start starts the conflux service via the Windows SCM.
//
// Inputs:
//   - s: *service. The Windows service.
//
// Outputs:
//   - err: error. Non-nil if the SCM call fails.
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

// Stop stops the conflux service via the Windows SCM.
//
// Inputs:
//   - s: *service. The Windows service.
//
// Outputs:
//   - err: error. Non-nil if the SCM call fails.
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

// Remove stops the service, deletes it from the SCM, and reports success.
//
// Inputs:
//   - s: *service. The Windows service.
//
// Outputs:
//   - err: error. Non-nil if a step fails.
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

// Status reports the conflux service status from the Windows SCM.
//
// Inputs:
//   - s: *service. The Windows service.
//
// Outputs:
//   - err: error. Non-nil if the SCM query fails.
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
	Logger.Sugar().Infof("VeilNet Conflux service status: %v", status)
	return nil
}

// Execute implements the Windows service handler: StartPending, start anchor, Running, then handle Stop, Shutdown, and Interrogate.
//
// Inputs:
//   - s: *service. The Windows service.
//   - args: []string. Service arguments.
//   - changeRequests: <-chan svc.ChangeRequest. Windows SCM control requests.
//   - changes: chan<- svc.Status. Windows SCM status updates.
//
// Outputs:
//   - ssec: bool. As required by the svc package.
//   - errno: uint32. As required by the svc package; 0 when the service stops.
func (s *service) Execute(args []string, changeRequests <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {

	// Signal the service is starting
	changes <- svc.Status{State: svc.StartPending}

	// Load the configuration
	config, err := anchor.LoadConfig()
	if err != nil {
		Logger.Sugar().Fatalf("failed to load configuration: %v", err)
		return
	}

	// Initialize the anchor plugin
	subprocess, err := anchor.NewAnchor()
	if err != nil {
		Logger.Sugar().Fatalf("failed to initialize anchor plugin: %v", err)
		return
	}
	defer subprocess.Process.Kill()

	// Wait for the subprocess to start
	time.Sleep(1 * time.Second)

	// Create a gRPC client connection
	anchor, err := anchor.NewAnchorClient()
	if err != nil {
		Logger.Sugar().Fatalf("failed to create anchor gRPC client: %v", err)
		return
	}

	// Start the anchor
	_, err = anchor.StartAnchor(context.Background(), &pb.StartAnchorRequest{
		GuardianUrl:  config.Guardian,
		AnchorToken:   config.Token,
		Ip:            config.IP,
		Portal:        !config.Rift,
	})
	if err != nil {
		Logger.Sugar().Fatalf("failed to start anchor: %v", err)
		return
	}

	// Set the status to running
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	// Monitor for service control requests and anchor context
	for changeRequest := range changeRequests {
		switch changeRequest.Cmd {
		case svc.Interrogate:
			changes <- changeRequest.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			anchor.StopAnchor(context.Background(), &emptypb.Empty{})
			changes <- svc.Status{State: svc.Stopped}
			return false, 0
		default:
			Logger.Sugar().Warnf("unexpected service control request: %v", changeRequest.Cmd)
			changes <- changeRequest.CurrentStatus
		}
	}
	return false, 0
}
