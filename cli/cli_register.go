package cli

import (
	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/service"
)

type Register struct {
	RegistrationToken string `short:"t" help:"The registration token" env:"VEILNET_REGISTRATION_TOKEN" json:"registration_token"`
	Guardian          string `help:"The Guardian URL (Authentication Server), default: https://guardian.veilnet.app" default:"https://guardian.veilnet.app" env:"VEILNET_GUARDIAN" json:"guardian"`
	Veil              string `help:"The veil URL, default: nats.veilnet.app" default:"nats.veilnet.app" env:"VEILNET_VEIL" json:"veil"`
	VeilPort          int    `help:"The veil port, default: 30422" default:"30422" env:"VEILNET_VEIL_PORT" json:"veil_port"`
	Portal            bool   `short:"p" help:"Enable portal mode, default: false" default:"false" env:"VEILNET_PORTAL" json:"portal"`
	Teams             string `help:"The teams to be forwarded by the conflux, separated by comma, e.g. team1,team2" env:"VEILNET_CONFLUX_TEAMS" json:"teams"`
	Tag               string `help:"The tag for the conflux" env:"VEILNET_CONFLUX_TAG" json:"tag"`
	Cidr              string `help:"The CIDR of the conflux" env:"VEILNET_CONFLUX_CIDR" json:"cidr"`
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
		Veil:              cmd.Veil,
		VeilPort:          cmd.VeilPort,
		Portal:            cmd.Portal,
		Teams:             cmd.Teams,
		Tag:               cmd.Tag,
		Cidr:              cmd.Cidr,
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
		Veil:      cmd.Veil,
		VeilPort:  cmd.VeilPort,
		Portal:    cmd.Portal,
	}

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
