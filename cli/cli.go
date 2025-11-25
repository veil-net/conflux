package cli

import (
	"fmt"

	"github.com/alecthomas/kong"
	"github.com/veil-net/veilnet"
)

type CLI struct {
	Version kong.VersionFlag `short:"v" help:"Print the version and exit"`
	Run     Run              `cmd:"run" default:"true" help:"Run the conflux service"`
	Install Install          `cmd:"install" help:"Install the conflux service, this will not update registration data"`
	Start   Start            `cmd:"start" help:"Start the conflux service"`
	Stop    Stop             `cmd:"stop" help:"Stop the conflux service"`
	Remove  Remove           `cmd:"remove" help:"Remove the conflux service, this will not update registration data"`
	Status  Status           `cmd:"status" help:"Get the status of the conflux service"`

	Register   Register   `cmd:"register" help:"Register a new conflux with a registration token, and reinstall the service"`
	Unregister Unregister `cmd:"unregister" help:"Unregister the conflux and remove the service"`
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
		return nil
	} else {
		veilnet.Logger.Sugar().Errorf("VeilNet service is not running.")
		return fmt.Errorf("VeilNet service is not running")
	}
}
