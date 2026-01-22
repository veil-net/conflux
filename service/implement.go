package service

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/veil-net/conflux/anchor"
	pb "github.com/veil-net/conflux/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)


type ServiceImpl struct {
}

func NewServiceImpl() *ServiceImpl {
	return &ServiceImpl{}
}

func (s *ServiceImpl) Run() {

	// Load the configuration
	config, err := anchor.LoadConfig()
	if err != nil {
		Logger.Sugar().Errorf("failed to load configuration: %v", err)
		return
	}

	// Initialize the anchor plugin
	anchor, cmd, err := anchor.NewAnchor()
	if err != nil {
		Logger.Sugar().Errorf("failed to initialize anchor plugin: %v", err)
		return
	}
	defer cmd.Process.Kill()

	// Initialize the anchor instance
	_, err = anchor.CreateAnchor(context.Background(), &emptypb.Empty{})
	if err != nil {
		Logger.Sugar().Errorf("failed to create anchor instance: %v", err)
		return
	}

	// Start the anchor
	_, err = anchor.StartAnchor(context.Background(), &pb.StartAnchorRequest{
		GuardianUrl:  config.Guardian,
		VeilUrl:       config.Veil,
		VeilPort:      int32(config.VeilPort),
		AnchorToken:   config.Token,
		Portal:        config.Portal,
	})
	if err != nil {
		Logger.Sugar().Errorf("failed to start anchor: %v", err)
		return
	}

	// Create the TUN device
	_, err = anchor.CreateTUN(context.Background(), &pb.CreateTUNRequest{
		Ifname: "veilnet",
		Mtu:    1500,
	})
	if err != nil {
		Logger.Sugar().Errorf("failed to create TUN device: %v", err)
		return
	}

	// Attach the anchor with the TUN device
	_, err = anchor.AttachWithTUN(context.Background(), &emptypb.Empty{})
	if err != nil {
		Logger.Sugar().Errorf("failed to attach anchor with TUN device: %v", err)
		return
	}

	// Wait for interrupt signal
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	// Wait for interrupt signal
	<-interrupt

	// Stop the anchor
	_, err = anchor.StopAnchor(context.Background(), &emptypb.Empty{})

	// Destroy the anchor
	_, err = anchor.DestroyAnchor(context.Background(), &emptypb.Empty{})

	// Destroy the TUN device
	_, err = anchor.DestroyTUN(context.Background(), &emptypb.Empty{})
}