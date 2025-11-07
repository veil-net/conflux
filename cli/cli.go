package cli

import (
	"github.com/alecthomas/kong"
	"github.com/veil-net/veilnet"
)

type CLI struct {
	Version kong.VersionFlag `short:"v" help:"Print the version and exit"`
	Run     Run              `cmd:"run" default:"true" help:"Run the conflux service"`
	Install Install          `cmd:"install" help:"Install the conflux service"`
	Start   Start            `cmd:"start" help:"Start the conflux service"`
	Stop    Stop             `cmd:"stop" help:"Stop the conflux service"`
	Remove  Remove           `cmd:"remove" help:"Remove the conflux service"`
	Status  Status           `cmd:"status" help:"Get the status of the conflux service"`
	Docker  Docker           `cmd:"docker" help:"Run the conflux service in docker"`

	Register   Register   `cmd:"register" help:"Register a new conflux with a registration token, and start the conflux"`
	Unregister Unregister `cmd:"unregister" help:"Unregister the conflux and stop the service"`
	Up         Up         `cmd:"up" help:"Start the conflux with a conflux token"`
	Down       Down       `cmd:"down" help:"Stop the conflux"`
}

type Run struct{}

func (cmd *Run) Run() error {
	conflux := NewConflux()
	err := conflux.Run()
	if err != nil {
		return err
	}
	return nil
}

type Install struct{}

func (cmd *Install) Run() error {
	conflux := NewConflux()
	err := conflux.Install()
	if err != nil {
		return err
	}
	return nil
}

type Start struct{}

func (cmd *Start) Run() error {
	conflux := NewConflux()
	err := conflux.Start()
	if err != nil {
		return err
	}
	return nil
}

type Stop struct{}

func (cmd *Stop) Run() error {
	conflux := NewConflux()
	err := conflux.Stop()
	if err != nil {
		return err
	}
	return nil
}

type Remove struct{}

func (cmd *Remove) Run() error {
	conflux := NewConflux()
	err := conflux.Remove()
	if err != nil {
		return err
	}
	return nil
}

type Status struct{}

func (cmd *Status) Run() error {
	conflux := NewConflux()
	status, err := conflux.Status()
	if err != nil {
		return err
	}
	if status {
		veilnet.Logger.Sugar().Infof("VeilNet service is running.")
	} else {
		veilnet.Logger.Sugar().Errorf("VeilNet service is not running.")
	}
	return nil
}

type Docker struct{
	Tag      string `help:"The tag for the conflux" env:"VEILNET_CONFLUX_TAG" json:"tag"`
	Cidr     string `help:"The CIDR of the conflux" env:"VEILNET_CONFLUX_CIDR" json:"cidr"`
	Token    string `short:"t" help:"The registration token" env:"VEILNET_REGISTRATION_TOKEN" json:"registration_token"`
	Guardian string `short:"g" help:"The Guardian URL (Authentication Server), default: https://guardian.veilnet.app" default:"https://guardian.veilnet.app" env:"VEILNET_GUARDIAN" json:"guardian"`
	Portal   bool   `short:"p" help:"Enable portal mode, default: false" default:"false" env:"VEILNET_PORTAL" json:"portal"`
	Subnets  string `help:"The subnets to be forwarded by the conflux , separated by comma, e.g. 10.128.0.0/16,10.129.0.0/16" env:"VEILNET_CONFLUX_SUBNETS" json:"subnets"`
}

func (cmd *Docker) Run() error {
	conflux := NewConflux()
	err := conflux.Run()
	if err != nil {
		return err
	}
	return nil
}
