package cli

import (
	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/service"
)

type Up struct {
	ConfluxID string   `short:"c" help:"The conflux ID, please keep it secret" env:"VEILNET_CONFLUX_ID" json:"conflux_id"`
	Token     string   `short:"t" help:"The conflux token, please keep it secret" env:"VEILNET_CONFLUX_TOKEN" json:"conflux_token"`
	Guardian  string   `help:"The Guardian URL (Authentication Server), default: https://guardian.veilnet.app" default:"https://guardian.veilnet.app" env:"VEILNET_GUARDIAN" json:"guardian"`
	Rift      bool     `short:"r" help:"Enable rift mode, default: false" default:"false" env:"VEILNET_RIFT" json:"rift"`
	IP        string   `help:"The IP of the conflux" env:"VEILNET_CONFLUX_IP" json:"ip"`
	Taints    []string `help:"Taints for the conflux, conflux can only communicate with other conflux with taints that are either a super set or a subset" env:"VEILNET_CONFLUX_TAINTS" json:"taints"`
	Debug     bool     `short:"d" help:"Enable debug mode, this will not install the service but run conflux directly" env:"VEILNET_DEBUG" json:"debug"`
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

	conflux := service.NewService()
	conflux.Run()

	return nil
}
