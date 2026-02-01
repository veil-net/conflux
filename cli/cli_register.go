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
	Rift              bool     `short:"r" help:"Enable rift mode, default: false" default:"false" env:"VEILNET_CONFLUX_RIFT" json:"rift"`
	Portal            bool     `short:"p" help:"Enable portal mode, default: false" default:"false" env:"VEILNET_CONFLUX_PORTAL" json:"portal"`
	Guardian          string   `help:"The Guardian URL (Authentication Server), default: https://guardian.veilnet.app" default:"https://guardian.veilnet.app" env:"VEILNET_GUARDIAN" json:"guardian"`
	Tag               string   `help:"The tag for the conflux" env:"VEILNET_CONFLUX_TAG" json:"tag"`
	IP                string   `help:"The IP of the conflux" env:"VEILNET_CONFLUX_IP" json:"ip"`
	JWT               string   `help:"The JWT for the conflux" env:"VEILNET_CONFLUX_JWT" json:"jwt"`
	JWKS_url          string   `help:"The JWKS URL for the conflux" env:"VEILNET_CONFLUX_JWKS_URL" json:"jwks_url"`
	Audience          string   `help:"The audience for the conflux" env:"VEILNET_CONFLUX_AUDIENCE" json:"audience"`
	Issuer            string   `help:"The issuer for the conflux" env:"VEILNET_CONFLUX_ISSUER" json:"issuer"`
	Taints            []string `help:"Taints for the conflux, conflux can only communicate with other conflux with taints that are either a super set or a subset" env:"VEILNET_CONFLUX_TAINTS" json:"taints"`
	Debug             bool     `short:"d" help:"Enable debug mode, this will not install the service but run conflux directly" env:"VEILNET_CONFLUX_DEBUG" json:"debug"`
	Tracer            bool     `help:"Enable tracer, default: false" default:"false" env:"VEILNET_TRACER" json:"tracer"`
	OTLPEndpoint      string   `help:"The OTLP endpoint for the metrics" env:"VEILNET_OTLP_ENDPOINT" json:"otlp_endpoint"`
	OTLPUseTLS        bool     `help:"Enable TLS for the metrics" default:"false" env:"VEILNET_OTLP_USE_TLS" json:"otlp_use_tls"`
	OTLPInsecure      bool     `help:"Enable insecure mode for the metrics" default:"false" env:"VEILNET_OTLP_INSECURE" json:"otlp_insecure"`
	OTLPCACert        string   `help:"The OTLP CA certificate for the metrics" env:"VEILNET_OTLP_CA_CERT" json:"otlp_ca_cert"`
	OTLPClientCert    string   `help:"The OTLP client certificate for the metrics" env:"VEILNET_OTLP_CLIENT_CERT" json:"otlp_client_cert"`
	OTLPClientKey     string   `help:"The OTLP client key for the metrics" env:"VEILNET_OTLP_CLIENT_KEY" json:"otlp_client_key"`
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
	tracerConfig := &anchor.TracerConfig{
		Enabled:  cmd.Tracer,
		UseTLS:   cmd.OTLPUseTLS,
		Endpoint: cmd.OTLPEndpoint,
		Insecure: cmd.OTLPInsecure,
		CAFile:   cmd.OTLPCACert,
		CertFile: cmd.OTLPClientCert,
		KeyFile:  cmd.OTLPClientKey,
	}
	config := &anchor.ConfluxConfig{
		ConfluxID: registrationResponse.ConfluxID,
		Token:     registrationResponse.Token,
		Guardian:  cmd.Guardian,
		Rift:      cmd.Rift,
		Portal:    cmd.Portal,
		IP:        cmd.IP,
		Taints:    cmd.Taints,
		Tracer:    tracerConfig,
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
		Portal:      config.Portal,
		Rift:        config.Rift,
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
