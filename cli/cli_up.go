package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/veil-net/conflux/anchor"
	pb "github.com/veil-net/conflux/proto"
	"github.com/veil-net/conflux/service"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Up struct {
	ConfluxID string   `short:"c" help:"The conflux ID, please keep it secret" env:"VEILNET_CONFLUX_ID" json:"conflux_id"`
	Token     string   `short:"t" help:"The conflux token, please keep it secret" env:"VEILNET_CONFLUX_TOKEN" json:"conflux_token"`
	Guardian  string   `help:"The Guardian URL (Authentication Server), default: https://guardian.veilnet.app" default:"https://guardian.veilnet.app" env:"VEILNET_GUARDIAN" json:"guardian"`
	Rift      bool     `short:"r" help:"Enable rift mode, default: false" default:"false" env:"VEILNET_CONFLUX_RIFT" json:"rift"`
	Portal    bool     `short:"p" help:"Enable portal mode, default: false" default:"false" env:"VEILNET_CONFLUX_PORTAL" json:"portal"`
	IP        string   `help:"The IP of the conflux" env:"VEILNET_CONFLUX_IP" json:"ip"`
	Taints    []string `help:"Taints for the conflux, conflux can only communicate with other conflux with taints that are either a super set or a subset" env:"VEILNET_CONFLUX_TAINTS" json:"taints"`
	Debug     bool     `short:"d" help:"Enable debug mode, this will not install the service but run conflux directly" env:"VEILNET_CONFLUX_DEBUG" json:"debug"`
}

func (cmd *Up) Run() error {
	// Parse the config
	config := &anchor.ConfluxConfig{
		ConfluxID: cmd.ConfluxID,
		Token:     cmd.Token,
		Guardian:  cmd.Guardian,
		Rift:      cmd.Rift,
		IP:        cmd.IP,
		Taints:    cmd.Taints,
	}

	// Save the configuration
	err := anchor.SaveConfig(config)
	if err != nil {
		Logger.Sugar().Errorf("failed to save configuration: %v", err)
		return err
	}

	if !cmd.Debug {
		// Install the service
		conflux := service.NewService()
		conflux.Remove()
		err = conflux.Install()
		if err != nil {
			Logger.Sugar().Errorf("failed to install service: %v", err)
			return err
		}
		return nil
	}


	// Initialize the anchor plugin
	subprocess, err := anchor.NewAnchor()
	if err != nil {
		Logger.Sugar().Errorf("failed to initialize anchor subprocess: %v", err)
		return err
	}

	// Wait for the subprocess to start
	time.Sleep(1 * time.Second)

	// Create a gRPC client connection
	anchor, err := anchor.NewAnchorClient()
	if err != nil {
		Logger.Sugar().Errorf("failed to create anchor gRPC client: %v", err)
		return err
	}

	// Start the anchor
	_, err = anchor.StartAnchor(context.Background(), &pb.StartAnchorRequest{
		GuardianUrl: config.Guardian,
		AnchorToken: config.Token,
		Ip:          config.IP,
		Rift:        config.Rift,
		Portal:      config.Portal,
	})
	if err != nil {
		Logger.Sugar().Errorf("failed to start anchor: %v", err)
		return err
	}

	// Add taints
	for _, taint := range config.Taints {
		_, err = anchor.AddTaint(context.Background(), &pb.AddTaintRequest{
			Taint: taint,
		})
		if err != nil {
			Logger.Sugar().Warnf("failed to add taint: %v", err)
			continue
		}
	}

	// Wait for interrupt signal
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	// Wait for interrupt signal
	<-interrupt

	// Stop the anchor
	_, err = anchor.StopAnchor(context.Background(), &emptypb.Empty{})
	if err != nil {
		Logger.Sugar().Errorf("failed to stop anchor: %v", err)
	}

	// Kill the anchor subprocess
	subprocess.Process.Kill()

	return nil
}
