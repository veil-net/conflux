package cli

import (
	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/service"
)

type Up struct {
	ConfluxID string `short:"c" help:"The conflux ID, please keep it secret" env:"VEILNET_CONFLUX_ID" json:"conflux_id"`
	Token     string `short:"t" help:"The conflux token, please keep it secret" env:"VEILNET_CONFLUX_TOKEN" json:"conflux_token"`
	Guardian  string `help:"The Guardian URL (Authentication Server), default: https://guardian.veilnet.app" default:"https://guardian.veilnet.app" env:"VEILNET_GUARDIAN" json:"guardian"`
	Veil      string `help:"The veil URL, default: nats.veilnet.app" default:"nats.veilnet.app" env:"VEILNET_VEIL" json:"veil"`
	VeilPort  int    `help:"The veil port, default: 30422" default:"30422" env:"VEILNET_VEIL_PORT" json:"veil_port"`
	Portal    bool   `short:"p" help:"Enable portal mode, default: false" default:"false" env:"VEILNET_PORTAL" json:"portal"`
}

func (cmd *Up) Run() error {
	// Parse the config
	config := &anchor.ConfluxConfig{
		ConfluxID: cmd.ConfluxID,
		Token:     cmd.Token,
		Guardian:  cmd.Guardian,
		Veil:      cmd.Veil,
		VeilPort:  cmd.VeilPort,
		Portal:    cmd.Portal,
	}

	// Save the configuration
	err := anchor.SaveConfig(config)
	if err != nil {
		Logger.Sugar().Errorf("failed to save configuration: %v", err)
		return err
	}

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
