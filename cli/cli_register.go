package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

type Register struct {
	Tag      string `help:"The tag for the conflux" env:"VEILNET_CONFLUX_TAG" json:"tag"`
	Cidr     string `help:"The CIDR of the conflux" env:"VEILNET_CONFLUX_CIDR" json:"cidr"`
	Token    string `short:"t" help:"The registration token" env:"VEILNET_REGISTRATION_TOKEN" json:"registration_token"`
	Guardian string `help:"The Guardian URL (Authentication Server), default: https://guardian.veilnet.app" default:"https://guardian.veilnet.app" env:"VEILNET_GUARDIAN" json:"guardian"`
	Portal   bool   `short:"p" help:"Enable portal mode, default: false" default:"false" env:"VEILNET_PORTAL" json:"portal"`
	Teams    string `help:"The teams to be forwarded by the conflux, separated by comma, e.g. team1,team2" env:"VEILNET_CONFLUX_TEAMS" json:"teams"`
	Veil     string `help:"The veil URL, default: nats.veilnet.app" default:"nats.veilnet.app" env:"VEILNET_VEIL" json:"veil"`
	VeilPort int    `help:"The veil port, default: 30422" default:"30422" env:"VEILNET_VEIL_PORT" json:"veil_port"`
	ID       string `kong:"-" json:"id"`
}

type ConfluxToken struct {
	ConfluxID string `json:"conflux_id"`
	Token     string `json:"token"`
}

func (cmd *Register) Run() error {

	// Check if the veilnet service is running
	conflux := NewConflux()
	conflux.Remove()

	// Register the conflux
	confluxToken, err := cmd.register()
	if err != nil {
		return err
	}

	// Save the registration data
	err = cmd.saveRegistrationData(confluxToken)
	if err != nil {
		return err
	}

	// Restart the conflux service
	err = conflux.Install()
	if err != nil {
		return err
	}

	return nil
}

func (cmd *Register) register() (*ConfluxToken, error) {
	// Marshal the request body
	body, err := json.Marshal(cmd)
	if err != nil {
		Logger.Sugar().Errorf("Failed to marshal register command: %v", err)
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Create the request
	url := fmt.Sprintf("%s/conflux/register", cmd.Guardian)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		Logger.Sugar().Errorf("Failed to create register request to Guardian: %v", err)
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Set the Authorization header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cmd.Token))
	req.Header.Set("Content-Type", "application/json")

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		Logger.Sugar().Errorf("Failed to make register request to Guardian: %v", err)
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// if the response is not 200, return an error
	if !(resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK) {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			Logger.Sugar().Errorf("Failed to read register response body: %v", err)
			return nil, fmt.Errorf("failed to read response body: %v", err)
		}
		return nil, fmt.Errorf("failed to register conflux: %s: %s", resp.Status, string(body))
	}

	// Read the response body
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		Logger.Sugar().Errorf("Failed to read register response: %v", err)
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Parse the response body
	var confluxToken ConfluxToken
	err = json.Unmarshal(body, &confluxToken)
	if err != nil {
		Logger.Sugar().Errorf("Failed to parse register response: %v", err)
		return nil, fmt.Errorf("failed to parse response body: %v", err)
	}
	return &confluxToken, nil
}

func (cmd *Register) loadRegistrationData() {
	// First load the registration data from file (if exists)
	confluxDir, err := getConfigDir()
	if err == nil {
		confluxFile := filepath.Join(confluxDir, "conflux.json")
		registrationDataFile, err := os.ReadFile(confluxFile)
		if err == nil {
			err = json.Unmarshal(registrationDataFile, &cmd)
			if err != nil {
				Logger.Sugar().Warnf("Failed to unmarshal registration data from file, using environment variables: %v", err)
			}
		}
	}

	// Then override with environment variables (ENV takes precedence)
	if envGuardian := os.Getenv("VEILNET_GUARDIAN"); envGuardian != "" {
		cmd.Guardian = envGuardian
	}
	if envToken := os.Getenv("VEILNET_REGISTRATION_TOKEN"); envToken != "" {
		cmd.Token = envToken
	}
	if envTag := os.Getenv("VEILNET_CONFLUX_TAG"); envTag != "" {
		cmd.Tag = envTag
	}
	if envCidr := os.Getenv("VEILNET_CONFLUX_CIDR"); envCidr != "" {
		cmd.Cidr = envCidr
	}
	if envPortal := os.Getenv("VEILNET_PORTAL"); envPortal != "" {
		cmd.Portal = envPortal == "true"
	}
	if envTeams := os.Getenv("VEILNET_CONFLUX_TEAMS"); envTeams != "" {
		cmd.Teams = envTeams
	}
	if envVeil := os.Getenv("VEILNET_VEIL"); envVeil != "" {
		cmd.Veil = envVeil
	}
	if envVeilPort := os.Getenv("VEILNET_VEIL_PORT"); envVeilPort != "" {
		cmd.VeilPort, err = strconv.Atoi(envVeilPort)
		if err != nil {
			Logger.Sugar().Warnf("Failed to convert veil port to int, using default: %v", err)
		}
	}
}

func (cmd *Register) saveRegistrationData(confluxToken *ConfluxToken) error {
	// Write the registration data to file
	confluxDir, err := getConfigDir()
	if err != nil {
		Logger.Sugar().Errorf("Failed to get config directory: %v", err)
		return fmt.Errorf("failed to get config directory: %v", err)
	}
	if err := os.MkdirAll(confluxDir, 0755); err != nil {
		Logger.Sugar().Errorf("Failed to create conflux directory: %v", err)
		return fmt.Errorf("failed to create conflux directory: %v", err)
	}
	confluxFile := filepath.Join(confluxDir, "conflux.json")
	cmd.ID = confluxToken.ConfluxID
	registrationData, err := json.Marshal(cmd)
	if err != nil {
		Logger.Sugar().Errorf("Failed to marshal registration data: %v", err)
		return fmt.Errorf("failed to marshal registration data: %v", err)
	}
	err = os.WriteFile(confluxFile, registrationData, 0644)
	if err != nil {
		Logger.Sugar().Errorf("Failed to write registration data: %v", err)
		return fmt.Errorf("failed to write registration data: %v", err)
	}
	Logger.Sugar().Infof("Registration data written to %s", confluxFile)
	return nil
}
