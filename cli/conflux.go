package cli

import "github.com/veil-net/veilnet/logger"

var Logger = logger.Logger

type Conflux interface {

	// Run runs the conflux service
	Run() error

	// Install installs the conflux service
	Install() error

	// Start starts the conflux service
	Start() error

	// Stop stops the conflux service
	Stop() error

	// Remove removes the conflux service
	Remove() error

	// Status returns the status of the conflux service
	Status() (bool, error)
}

func NewConflux() Conflux {
	return newConflux()
}
