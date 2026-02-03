package cli

import (
	"github.com/veil-net/conflux/service"
	"github.com/veil-net/conflux/anchor"
)

// Unregister unregisters the conflux and removes the service; requires the registration token.
type Unregister struct {
	RegistrationToken string `short:"t" help:"The registration token" env:"VEILNET_REGISTRATION_TOKEN" json:"registration_token"`
}

// Run unregisters the conflux with the guardian, deletes config, and removes the service.
//
// Inputs:
//   - cmd: *Unregister. The registration token.
//
// Outputs:
//   - err: error. Non-nil if any step fails.
func (cmd *Unregister) Run() error {

	// Load the configuration
	config, err := anchor.LoadConfig()
	if err != nil {
		Logger.Sugar().Errorf("failed to load configuration, this instance may not registered: %v", err)
		return err
	}

	// Unregister the conflux
	err = anchor.UnregisterConflux(cmd.RegistrationToken, config)
	if err != nil {
		Logger.Sugar().Errorf("failed to unregister conflux: %v", err)
		return err
	}

	// Delete the configuration
	err = anchor.DeleteConfig()
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
