package cli

import (
	"fmt"
	"os"
	"path/filepath"

)

type Down struct{}

func (cmd *Down) Run() error {
	conflux := NewConflux()
	conflux.Remove()

	// Remove the up.json file
	tmpDir, err := os.UserConfigDir()
	if err != nil {
		Logger.Sugar().Warnf("Failed to get user config directory: %v", err)
	} else {
		confluxDir := filepath.Join(tmpDir, "conflux")
		envFile := filepath.Join(confluxDir, "up.json")
		err = os.Remove(envFile)
		if err != nil && !os.IsNotExist(err) {
			Logger.Sugar().Errorf("Failed to remove environment data file: %v", err)
			return fmt.Errorf("failed to remove environment data file: %v", err)
		}
	}

	return nil
}