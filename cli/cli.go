// Package cli provides CLI commands and kong-based parsing for the VeilNet Conflux.
package cli

import (
	"github.com/alecthomas/kong"
	"github.com/veil-net/conflux/logger"
	"github.com/veil-net/conflux/service"
)

// Logger re-exports the global logger for CLI use.
var Logger = logger.Logger

// CLI is the root command with run, install, start, stop, remove, status and up, down, register, unregister, info, taint subcommands.
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

// Run runs the conflux service in the foreground.
type Run struct{}

// Run executes the run command.
//
// Inputs:
//   - cmd: *Run. The command with parsed flags.
//
// Outputs:
//   - err: error. Non-nil to be reported to the user.
func (cmd *Run) Run() error {
	Logger.Sugar().Infof("Starting VeilNet Conflux...")
	conflux := service.NewService()
	conflux.Run()
	return nil
}

// Install installs the conflux service without updating registration data.
type Install struct{}

// Run executes the install command.
//
// Inputs:
//   - cmd: *Install. The command with parsed flags.
//
// Outputs:
//   - err: error. Non-nil to be reported to the user.
func (cmd *Install) Run() error {
	conflux := service.NewService()
	return conflux.Install()
}

// Start starts the conflux service.
type Start struct{}

// Run executes the start command.
//
// Inputs:
//   - cmd: *Start. The command with parsed flags.
//
// Outputs:
//   - err: error. Non-nil to be reported to the user.
func (cmd *Start) Run() error {
	conflux := service.NewService()
	return conflux.Start()
}

// Stop stops the conflux service.
type Stop struct{}

// Run executes the stop command.
//
// Inputs:
//   - cmd: *Stop. The command with parsed flags.
//
// Outputs:
//   - err: error. Non-nil to be reported to the user.
func (cmd *Stop) Run() error {
	conflux := service.NewService()
	return conflux.Stop()
}

// Remove removes the conflux service without updating registration data.
type Remove struct{}

// Run executes the remove command.
//
// Inputs:
//   - cmd: *Remove. The command with parsed flags.
//
// Outputs:
//   - err: error. Non-nil to be reported to the user.
func (cmd *Remove) Run() error {
	conflux := service.NewService()
	return conflux.Remove()
}

// Status reports the status of the conflux service.
type Status struct{}

// Run executes the status command.
//
// Inputs:
//   - cmd: *Status. The command with parsed flags.
//
// Outputs:
//   - err: error. Non-nil to be reported to the user.
func (cmd *Status) Run() error {
	conflux := service.NewService()
	return conflux.Status()
}
