package cli

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/veil-net/veilnet"
)

type Unregister struct {
}

func (cmd *Unregister) Run() error {
	// Load the registration data
	register := Register{}
	register.loadRegistrationData()

	if register.ID == "" {
		veilnet.Logger.Sugar().Errorf("Confux ID is missing in the registration data")
		return fmt.Errorf("conflux ID is missing in the registration data")
	}

	if register.Guardian == "" {
		veilnet.Logger.Sugar().Errorf("Guardian URL is missing in the registration data")
		return fmt.Errorf("guardian URL is missing in the registration data")
	}

	if register.Token == "" {
		veilnet.Logger.Sugar().Errorf("Registration token is missing in the registration data")
		return fmt.Errorf("registration token is missing in the registration data")
	}

	// Parse the request URL
	url := fmt.Sprintf("%s/conflux/unregister?conflux_id=%s", register.Guardian, register.ID)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		veilnet.Logger.Sugar().Errorf("Failed to create unregister request: %v", err)
		return fmt.Errorf("failed to create unregister request: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", register.Token))
	req.Header.Set("Content-Type", "application/json")

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		veilnet.Logger.Sugar().Errorf("Failed to make unregister request: %v", err)
		return fmt.Errorf("failed to make unregister request: %v", err)
	}
	defer resp.Body.Close()

	// if the response is not 200, return an error
	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			veilnet.Logger.Sugar().Errorf("Failed to read unregister response body: %v", err)
			return fmt.Errorf("failed to read unregister response body: %v", err)
		}
		return fmt.Errorf("failed to unregister conflux: %s: %s", resp.Status, string(body))
	}

	// Remove the conflux file
	tmpDir, err := os.UserConfigDir()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("Failed to get user config directory: %v", err)
		return fmt.Errorf("failed to get user config directory: %v", err)
	}
	confluxDir := filepath.Join(tmpDir, "conflux")
	confluxFile := filepath.Join(confluxDir, "conflux.json")
	err = os.Remove(confluxFile)
	if err != nil {
		veilnet.Logger.Sugar().Errorf("Failed to remove conflux file: %v", err)
		return fmt.Errorf("failed to remove conflux file: %v", err)
	}

	// Stop the conflux service
	conflux := NewConflux()
	conflux.Remove()

	veilnet.Logger.Sugar().Infof("Unregistration successful, VeilNet service stopped and conflux file removed")

	return nil
}
