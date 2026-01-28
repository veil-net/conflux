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

type Register struct {
	RegistrationToken string   `short:"t" help:"The registration token" env:"VEILNET_REGISTRATION_TOKEN" json:"registration_token"`
	Rift              bool     `short:"r" help:"Enable rift mode, default: false" default:"false" env:"VEILNET_RIFT" json:"rift"`
	Guardian          string   `help:"The Guardian URL (Authentication Server), default: https://guardian.veilnet.app" default:"https://guardian.veilnet.app" env:"VEILNET_GUARDIAN" json:"guardian"`
	Tag               string   `help:"The tag for the conflux" env:"VEILNET_CONFLUX_TAG" json:"tag"`
	IP                string   `help:"The IP of the conflux" env:"VEILNET_CONFLUX_IP" json:"ip"`
	JWT               string   `help:"The JWT for the conflux" env:"VEILNET_CONFLUX_JWT" json:"jwt"`
	JWKS_url          string   `help:"The JWKS URL for the conflux" env:"VEILNET_CONFLUX_JWKS_URL" json:"jwks_url"`
	Audience          string   `help:"The audience for the conflux" env:"VEILNET_CONFLUX_AUDIENCE" json:"audience"`
	Issuer            string   `help:"The issuer for the conflux" env:"VEILNET_CONFLUX_ISSUER" json:"issuer"`
	Taints            []string `help:"Taints for the conflux, conflux can only communicate with other conflux with taints that are either a super set or a subset" env:"VEILNET_CONFLUX_TAINTS" json:"taints"`
	Debug             bool     `short:"d" help:"Enable debug mode, this will not install the service but run conflux directly" env:"VEILNET_DEBUG" json:"debug"`
}

type ConfluxToken struct {
	ConfluxID string `json:"conflux_id"`
	Token     string `json:"token"`
}

func (cmd *Register) Run() error {

	// Parse the command
	registrationRequest := &anchor.ResgitrationRequest{
		RegistrationToken: cmd.RegistrationToken,
		Guardian:          cmd.Guardian,
		Tag:               cmd.Tag,
		JWT:               cmd.JWT,
		JWKS_url:          cmd.JWKS_url,
		Audience:          cmd.Audience,
		Issuer:            cmd.Issuer,
	}

	// Register the conflux
	registrationResponse, err := anchor.RegisterConflux(registrationRequest)
	if err != nil {
		Logger.Sugar().Errorf("failed to register conflux: %v", err)
		return err
	}

	// Save the configuration
	config := &anchor.ConfluxConfig{
		ConfluxID: registrationResponse.ConfluxID,
		Token:     registrationResponse.Token,
		Guardian:  cmd.Guardian,
		Rift:      cmd.Rift,
		IP:        cmd.IP,
		Taints:    cmd.Taints,
	}

	if !cmd.Debug {
		// Save the configuration
		err = anchor.SaveConfig(config)
		if err != nil {
			Logger.Sugar().Errorf("failed to save configuration: %v", err)
			return err
		}

		// Install the service
		conflux := service.NewService()
		if err := conflux.Status(); err == nil {
			Logger.Sugar().Infof("reinstalling veilnet conflux service...")
			conflux.Remove()
		} else {
			Logger.Sugar().Infof("installing veilnet conflux service...")
		}
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
		Portal:      !config.Rift,
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

	// Create the TUN device
	_, err = anchor.CreateTUN(context.Background(), &pb.CreateTUNRequest{
		Ifname: "veilnet",
		Mtu:    1500,
	})
	if err != nil {
		Logger.Sugar().Errorf("failed to create TUN device: %v", err)
		return err
	}

	// Attach the anchor with the TUN device
	_, err = anchor.AttachWithTUN(context.Background(), &emptypb.Empty{})
	if err != nil {
		Logger.Sugar().Errorf("failed to attach anchor with TUN device: %v", err)
		return err
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

	// Destroy the TUN device
	_, err = anchor.DestroyTUN(context.Background(), &emptypb.Empty{})
	if err != nil {
		Logger.Sugar().Errorf("failed to destroy TUN device: %v", err)
	}

	// Kill the anchor subprocess
	subprocess.Process.Kill()

	return nil
}
