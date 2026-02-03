package cli

import (
	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/service"
)

// Down stops the veilnet service and removes the conflux token.
type Down struct{}

// Run deletes the configuration and removes the conflux service.
//
// Inputs:
//   - cmd: *Down. The down command.
//
// Outputs:
//   - err: error. Non-nil if either step fails.
func (cmd *Down) Run() error {
	// Delete the configuration
	err := anchor.DeleteConfig()
	if err != nil {
		Logger.Sugar().Errorf("failed to delete configuration: %v", err)
		return err
	}

	// Remove the service
	conflux := service.NewService()
	err = conflux.Remove()
	if err != nil {
		Logger.Sugar().Errorf("failed to remove service: %v", err)
		return err
	}

	return nil
}