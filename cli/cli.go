package cli

import (
	"github.com/alecthomas/kong"
	"github.com/veil-net/conflux/logger"
	"github.com/veil-net/conflux/service"
)

var Logger = logger.Logger

type CLI struct {
	Version kong.VersionFlag `short:"v" help:"Print the version and exit"`
	Run     Run              `cmd:"run" default:"true" help:"Run the conflux service"`
	Install Install          `cmd:"install" help:"Install the conflux service, this will not update registration data"`
	Start   Start            `cmd:"start" help:"Start the conflux service"`
	Stop    Stop             `cmd:"stop" help:"Stop the conflux service"`
	Remove  Remove           `cmd:"remove" help:"Remove the conflux service, this will not update registration data"`
	Status  Status           `cmd:"status" help:"Get the status of the conflux service"`

	Up         Up         `cmd:"up" help:"Start the veilnet service with a conflux token"`
	Down       Down       `cmd:"down" help:"Stop the veilnet service and remove the conflux token"`
	Register   Register   `cmd:"register" help:"Register a new conflux with a registration token, and reinstall the service"`
	Unregister Unregister `cmd:"unregister" help:"Unregister the conflux and remove the service"`
	Info       Info       `cmd:"info" help:"Get the info of the conflux"`
	Taint      Taint      `cmd:"taint" help:"Add or remove taints"`
}

type Run struct{}

func (cmd *Run) Run() error {
	Logger.Sugar().Infof("Starting VeilNet Conflux...")
	conflux := service.NewService()
	conflux.Run()
	return nil
}

type Install struct{}

func (cmd *Install) Run() error {
	conflux := service.NewService()
	return conflux.Install()
}

type Start struct{}

func (cmd *Start) Run() error {
	conflux := service.NewService()
	return conflux.Start()
}

type Stop struct{}

func (cmd *Stop) Run() error {
	conflux := service.NewService()
	return conflux.Stop()
}

type Remove struct{}

func (cmd *Remove) Run() error {
	conflux := service.NewService()
	return conflux.Remove()
}

type Status struct{}

func (cmd *Status) Run() error {
	conflux := service.NewService()
	return conflux.Status()
}
