package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/veil-net/veilnet"
)

type Register struct {
	Tag      string `help:"The tag for the conflux" env:"VEILNET_CONFLUX_TAG" json:"tag"`
	Cidr     string `help:"The CIDR of the conflux" env:"VEILNET_CONFLUX_CIDR" json:"cidr"`
	Token    string `short:"t" help:"The registration token" env:"VEILNET_REGISTRATION_TOKEN" json:"registration_token"`
	Guardian string `short:"g" help:"The Guardian URL (Authentication Server), default: https://guardian.veilnet.app" default:"https://guardian.veilnet.app" env:"VEILNET_GUARDIAN" json:"guardian"`
	Portal   bool   `short:"p" help:"Enable portal mode, default: false" default:"false" env:"VEILNET_PORTAL" json:"portal"`
	Teams    string `help:"The teams to be forwarded by the conflux, separated by comma, e.g. team1,team2" env:"VEILNET_CONFLUX_TEAMS" json:"teams"`
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
		veilnet.Logger.Sugar().Errorf("Failed to marshal register command: %v", err)
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Create the request
	url := fmt.Sprintf("%s/conflux/register", cmd.Guardian)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		veilnet.Logger.Sugar().Errorf("Failed to create register request to Guardian: %v", err)
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Set the Authorization header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cmd.Token))
	req.Header.Set("Content-Type", "application/json")

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		veilnet.Logger.Sugar().Errorf("Failed to make register request to Guardian: %v", err)
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// if the response is not 200, return an error
	if !(resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK) {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			veilnet.Logger.Sugar().Errorf("Failed to read register response body: %v", err)
			return nil, fmt.Errorf("failed to read response body: %v", err)
		}
		return nil, fmt.Errorf("failed to register conflux: %s: %s", resp.Status, string(body))
	}

	// Read the response body
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		veilnet.Logger.Sugar().Errorf("Failed to read register response: %v", err)
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Parse the response body
	var confluxToken ConfluxToken
	err = json.Unmarshal(body, &confluxToken)
	if err != nil {
		veilnet.Logger.Sugar().Errorf("Failed to parse register response: %v", err)
		return nil, fmt.Errorf("failed to parse response body: %v", err)
	}
	return &confluxToken, nil
}

func (cmd *Register) loadRegistrationData() {
	// Load the registration data from ENV
	cmd.Guardian = os.Getenv("VEILNET_GUARDIAN")
	cmd.Token = os.Getenv("VEILNET_REGISTRATION_TOKEN")
	cmd.Tag = os.Getenv("VEILNET_CONFLUX_TAG")
	cmd.Cidr = os.Getenv("VEILNET_CONFLUX_CIDR")
	cmd.Portal = os.Getenv("VEILNET_PORTAL") == "true"
	cmd.Teams = os.Getenv("VEILNET_CONFLUX_TEAMS")

	// Then load the registration data from file
	tmpDir, err := os.UserConfigDir()
	if err != nil {
		veilnet.Logger.Sugar().Warnf("Failed to get user config directory, using environment variables: %v", err)
		return
	}
	confluxDir := filepath.Join(tmpDir, "conflux")
	confluxFile := filepath.Join(confluxDir, "conflux.json")
	registrationDataFile, err := os.ReadFile(confluxFile)
	if err != nil {
		veilnet.Logger.Sugar().Warnf("Failed to read registration data from file, using environment variables: %v", err)
		return
	}
	err = json.Unmarshal(registrationDataFile, cmd)
	if err != nil {
		veilnet.Logger.Sugar().Warnf("Failed to unmarshal registration data from file, using environment variables: %v", err)
		return
	}
}

func (cmd *Register) saveRegistrationData(confluxToken *ConfluxToken) error {
	// Write the registration data to file
	tmpDir, err := os.UserConfigDir()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("Failed to get user config directory: %v", err)
		return fmt.Errorf("failed to get user config directory: %v", err)
	}
	confluxDir := filepath.Join(tmpDir, "conflux")
	if err := os.MkdirAll(confluxDir, 0755); err != nil {
		veilnet.Logger.Sugar().Errorf("Failed to create conflux directory: %v", err)
		return fmt.Errorf("failed to create conflux directory: %v", err)
	}
	confluxFile := filepath.Join(confluxDir, "conflux.json")
	cmd.ID = confluxToken.ConfluxID
	resitrationData, err := json.Marshal(cmd)
	if err != nil {
		veilnet.Logger.Sugar().Errorf("Failed to marshal registration data: %v", err)
		return fmt.Errorf("failed to marshal registration data: %v", err)
	}
	err = os.WriteFile(confluxFile, resitrationData, 0644)
	if err != nil {
		veilnet.Logger.Sugar().Errorf("Failed to write registration data: %v", err)
		return fmt.Errorf("failed to write registration data: %v", err)
	}
	veilnet.Logger.Sugar().Infof("Registration data written to %s", confluxFile)
	return nil
}
