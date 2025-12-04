package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Up struct {
	Guardian string `help:"The Guardian URL (Authentication Server), default: https://guardian.veilnet.app" default:"https://guardian.veilnet.app" env:"VEILNET_GUARDIAN" json:"guardian"`
	Veil     string `help:"The veil URL, default: nats.veilnet.app" default:"nats.veilnet.app" env:"VEILNET_VEIL" json:"veil"`
	VeilPort int    `help:"The veil port, default: 30422" default:"30422" env:"VEILNET_VEIL_PORT" json:"veil_port"`
	Token    string `short:"t" help:"The conflux token, please keep it secret" env:"VEILNET_CONFLUX_TOKEN" json:"conflux_token"`
	Portal   bool   `short:"p" help:"Enable portal mode, default: false" default:"false" env:"VEILNET_PORTAL" json:"portal"`
}

func (cmd *Up) Run() error {

	if cmd.Token == "" {
		Logger.Sugar().Errorf("conflux token is required")
		return fmt.Errorf("conflux token is required")
	}

	if cmd.Guardian == "" {
		Logger.Sugar().Errorf("guardian URL is required")
		return fmt.Errorf("guardian URL is required")
	}

	conflux := NewConflux()
	conflux.Remove()

	// Save environment variables to file
	err := cmd.saveUpData()
	if err != nil {
		return err
	}

	err = conflux.Install()
	if err != nil {
		return err
	}
	return nil
}

func (cmd *Up) loadUpData() {
	// First load the environment data from file (if exists)
	confluxDir, err := getConfigDir()
	if err == nil {
		envFile := filepath.Join(confluxDir, "up.json")
		envDataFile, err := os.ReadFile(envFile)
		if err == nil {
			err = json.Unmarshal(envDataFile, &cmd)
			if err != nil {
				Logger.Sugar().Warnf("Failed to unmarshal environment data from file, using environment variables: %v", err)
			}
		}
	}

	// Then override with environment variables (ENV takes precedence)
	if envGuardian := os.Getenv("VEILNET_GUARDIAN"); envGuardian != "" {
		cmd.Guardian = envGuardian
	}
	if envToken := os.Getenv("VEILNET_CONFLUX_TOKEN"); envToken != "" {
		cmd.Token = envToken
	}
	if envPortal := os.Getenv("VEILNET_PORTAL"); envPortal != "" {
		cmd.Portal = envPortal == "true"
	}
}

func (cmd *Up) saveUpData() error {
	// Write the environment data to file
	confluxDir, err := getConfigDir()
	if err != nil {
		Logger.Sugar().Errorf("Failed to get config directory: %v", err)
		return fmt.Errorf("failed to get config directory: %v", err)
	}
	if err := os.MkdirAll(confluxDir, 0755); err != nil {
		Logger.Sugar().Errorf("Failed to create conflux directory: %v", err)
		return fmt.Errorf("failed to create conflux directory: %v", err)
	}
	envFile := filepath.Join(confluxDir, "up.json")
	envData, err := json.Marshal(cmd)
	if err != nil {
		Logger.Sugar().Errorf("Failed to marshal environment data: %v", err)
		return fmt.Errorf("failed to marshal environment data: %v", err)
	}
	err = os.WriteFile(envFile, envData, 0644)
	if err != nil {
		Logger.Sugar().Errorf("Failed to write environment data: %v", err)
		return fmt.Errorf("failed to write environment data: %v", err)
	}
	Logger.Sugar().Infof("Environment data written to %s", envFile)
	return nil
}
