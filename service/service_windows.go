//go:build windows
// +build windows

package service

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/veil-net/conflux/anchor"
	pb "github.com/veil-net/conflux/proto"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const windowsServiceName = "VeilNet Conflux"

// service is the Windows implementation holding the ServiceImpl; it implements svc.Handler via Execute.
type service struct {
	serviceImpl *ServiceImpl
}

func installEventSource() error {
	err := eventlog.InstallAsEventCreate(windowsServiceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		// Treat "already exists" as success so reinstall flows remain idempotent.
		if strings.Contains(strings.ToLower(err.Error()), "exists") {
			return nil
		}
		return err
	}
	return nil
}

func removeEventSource() error {
	err := eventlog.Remove(windowsServiceName)
	if err != nil {
		// Event source may already be removed.
		if strings.Contains(strings.ToLower(err.Error()), "cannot find the file") ||
			strings.Contains(strings.ToLower(err.Error()), "not exist") {
			return nil
		}
		return err
	}
	return nil
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
		svc.Run(windowsServiceName, s)
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
	service, err := m.CreateService(windowsServiceName, exe, cfg)
	if err != nil {
		Logger.Sugar().Errorf("failed to create service: %v", err)
		return err
	}
	defer service.Close()

	if err := installEventSource(); err != nil {
		Logger.Sugar().Warnf("failed to install Windows event source: %v", err)
	}

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
	service, err := m.OpenService(windowsServiceName)
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
	service, err := m.OpenService(windowsServiceName)
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
	service, err := m.OpenService(windowsServiceName)
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

	if err := removeEventSource(); err != nil {
		Logger.Sugar().Warnf("failed to remove Windows event source: %v", err)
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
	service, err := m.OpenService(windowsServiceName)
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
	elog, elogErr := eventlog.Open(windowsServiceName)
	if elogErr == nil {
		defer elog.Close()
		_ = elog.Info(1000, "service starting")
	}

	// Signal the service is starting
	changes <- svc.Status{State: svc.StartPending}

	// Load the configuration
	config, err := anchor.LoadConfig()
	if err != nil {
		if elog != nil {
			_ = elog.Error(3001, "failed to load configuration: "+err.Error())
		}
		return
	}

	// Initialize the anchor plugin
	subprocess, err := anchor.NewAnchor()
	if err != nil {
		// Fallback path for Windows services: start the already-extracted temp binary
		// without inheriting stdout/stderr handles from the service process.
		pluginPath := filepath.Join(os.TempDir(), "anchor.exe")
		cmd := exec.Command(pluginPath)
		if startErr := cmd.Start(); startErr != nil {
			if elog != nil {
				_ = elog.Error(3002, "failed to initialize anchor plugin: "+err.Error()+"; inline start failed: "+startErr.Error())
			}
			return
		}
		if cmd.Process == nil {
			if elog != nil {
				_ = elog.Error(3002, "failed to initialize anchor plugin: inline process was nil")
			}
			return
		}
		subprocess = cmd
		if elog != nil {
			_ = elog.Warning(2002, "anchor initialized via inline subprocess fallback")
		}
	}
	defer subprocess.Process.Kill()

	// Wait for the subprocess to start
	time.Sleep(1 * time.Second)

	// Create a gRPC client connection
	anchor, err := anchor.NewAnchorClient()
	if err != nil {
		if elog != nil {
			_ = elog.Error(3003, "failed to create anchor gRPC client: "+err.Error())
		}
		return
	}

	var tracerConfig *pb.TracerConfig
	if config.Tracer != nil {
		tracerConfig = &pb.TracerConfig{
			Enabled:  config.Tracer.Enabled,
			Endpoint: config.Tracer.Endpoint,
			UseTls:   config.Tracer.UseTLS,
			Insecure: config.Tracer.Insecure,
			Ca:       config.Tracer.CAFile,
			Cert:     config.Tracer.CertFile,
			Key:      config.Tracer.KeyFile,
		}
	}

	// Start the anchor
	_, err = anchor.StartAnchor(context.Background(), &pb.StartAnchorRequest{
		GuardianUrl: config.Guardian,
		AnchorToken: config.Token,
		Ip:          config.IP,
		Rift:        config.Rift,
		Portal:      config.Portal,
		Conduit:     config.Conduit,
		Tracer:      tracerConfig,
	})
	if err != nil {
		if elog != nil {
			_ = elog.Error(3004, "failed to start anchor: "+err.Error())
		}
		return
	}

	// Set the status to running
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	if elog != nil {
		_ = elog.Info(1001, "service running")
	}

	// Monitor for service control requests and anchor context
	for changeRequest := range changeRequests {
		switch changeRequest.Cmd {
		case svc.Interrogate:
			changes <- changeRequest.CurrentStatus
		case svc.Stop, svc.Shutdown:
			// changes <- svc.Status{State: svc.StopPending}
			// anchor.StopAnchor(context.Background(), &emptypb.Empty{})
			if elog != nil {
				_ = elog.Info(1002, "service stopping")
			}
			changes <- svc.Status{State: svc.Stopped}
			return false, 0
		default:
			if elog != nil {
				_ = elog.Warning(2001, "unexpected service control request")
			}
			changes <- changeRequest.CurrentStatus
		}
	}
	return false, 0
}
