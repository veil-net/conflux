package cli

import (
	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/service"
)

type Down struct{}

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