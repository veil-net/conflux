package service

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/veil-net/conflux/anchor"
	pb "github.com/veil-net/conflux/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ServiceImpl is the concrete implementation that runs the anchor (load config, start subprocess, gRPC client, handle signals).
type ServiceImpl struct {
}

// NewServiceImpl returns a new ServiceImpl.
//
// Inputs: none.
//
// Outputs:
//   - *ServiceImpl. A new ServiceImpl.
func NewServiceImpl() *ServiceImpl {
	return &ServiceImpl{}
}

// Run runs the anchor in the foreground until interrupt (loads config, starts subprocess and gRPC client, handles signals).
//
// Inputs:
//   - s: *ServiceImpl. The implementation; uses config from the default config file.
//
// Outputs: none. Does not return; runs until process interrupt (SIGINT/SIGTERM).
func (s *ServiceImpl) Run() {

	// Load the configuration
	config, err := anchor.LoadConfig()
	if err != nil {
		Logger.Sugar().Errorf("failed to load configuration: %v", err)
		return
	}

	// Initialize the anchor plugin
	subprocess, err := anchor.NewAnchor()
	if err != nil {
		Logger.Sugar().Errorf("failed to initialize anchor subprocess: %v", err)
		return
	}
	defer subprocess.Process.Kill()

	// Wait for the subprocess to start
	time.Sleep(1 * time.Second)

	// Create a gRPC client connection
	anchor, err := anchor.NewAnchorClient()
	if err != nil {
		Logger.Sugar().Errorf("failed to create anchor gRPC client: %v", err)
		return
	}

	// Start the anchor
	_, err = anchor.StartAnchor(context.Background(), &pb.StartAnchorRequest{
		GuardianUrl: config.Guardian,
		AnchorToken: config.Token,
		Ip:          config.IP,
		Portal:      !config.Rift,
		Tracer: &pb.TracerConfig{
			Enabled:  config.Tracer.Enabled,
			Endpoint: config.Tracer.Endpoint,
			UseTls:   config.Tracer.UseTLS,
			Insecure: config.Tracer.Insecure,
			Ca:       config.Tracer.CAFile,
			Cert:     config.Tracer.CertFile,
			Key:      config.Tracer.KeyFile,
		},
	})
	if err != nil {
		Logger.Sugar().Errorf("failed to start anchor: %v", err)
		return
	}

	// Add taints
	for _, taint := range config.Taints {
		_, err = anchor.AddTaint(context.Background(), &pb.AddTaintRequest{
			Taint: taint,
		})
		if err != nil {
			Logger.Sugar().Errorf("failed to add taint: %v", err)
			return
		}
	}

	// Wait for interrupt signal
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	// Wait for interrupt signal
	<-interrupt

	// Stop the anchor
	_, err = anchor.StopAnchor(context.Background(), &emptypb.Empty{})

}
