// Package service provides platform-specific service install, start, stop, remove, and status for conflux.
package service

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/veil-net/conflux/logger"
)

// Logger re-exports the global logger for the service package.
var Logger = logger.Logger

// Service is the interface for running and managing the conflux service (Run, Install, Start, Stop, Remove, Status).
type Service interface {
	Run() error
	Install() error
	Start() error
	Stop() error
	Remove() error
	Status() error
}

// NewService returns the platform-specific Service implementation.
//
// Inputs: none.
//
// Outputs:
//   - Service. The platform-specific implementation (Linux systemd, Darwin launchd, Windows SCM).
func NewService() Service {
	return newService()
}

// ExecuteCmd runs a command and forwards stderr; returns an error on failure.
//
// Inputs:
//   - cmd: ...string. Program name and arguments (e.g. "systemctl", "start", "veilnet").
//
// Outputs:
//   - err: error. Non-nil if the command fails. Stderr is forwarded to os.Stderr.
func ExecuteCmd(cmd ...string) error {
	command := exec.Command(cmd[0], cmd[1:]...)
	command.Stderr = os.Stderr
	err := command.Run()
	if err != nil {
		return fmt.Errorf("failed to execute command %s, error: %w", cmd, err)
	}
	return nil
}