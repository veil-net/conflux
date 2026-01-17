package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/veil-net/conflux/logger"
)

var Logger = logger.Logger

type Config struct {
	RegistrationToken string `json:"registration_token" validate:"required"`
	Guardian          string `json:"guardian" validate:"required"`
	Veil              string `json:"veil" validate:"required"`
	VeilPort          int    `json:"veil_port" validate:"required"`
	Portal            bool   `json:"portal" validate:"required"`
	Teams             string `json:"teams"`
	Tag               string `json:"tag"`
	Cidr              string `json:"cidr"`
}

type ConfluxConfig struct {
	Token    string `json:"conflux_token" validate:"required"`
	Guardian string `json:"guardian" validate:"required"`
	Veil     string `json:"veil" validate:"required"`
	VeilPort int    `json:"veil_port" validate:"required"`
	Portal   bool   `json:"portal" validate:"required"`
}

type RegistrationResponse struct {
	ConfluxID string `json:"conflux_id" validate:"required"`
	Token     string `json:"token" validate:"required"`
}

func getConfigDir() (string, error) {
	var configDir string

	switch runtime.GOOS {
	case "windows":
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = "C:\\ProgramData"
		}
		configDir = filepath.Join(programData, "conflux")
	case "darwin":
		configDir = "/var/root/Library/Application Support/conflux"
	default:
		configDir = "/root/.config/conflux"
	}

	return configDir, nil
}

func loadConfig() (*Config, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return nil, err
	}
	configFilePath := filepath.Join(configDir, "conflux.json")
	configFile, err := os.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}
	config := &Config{}
	err = json.Unmarshal(configFile, config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func saveConfig(config *Config) error {
	configDir, err := getConfigDir()
	if err != nil {
		return err
	}
	configFilePath := filepath.Join(configDir, "conflux.json")
	configFile, err := json.Marshal(config)
	if err != nil {
		return err
	}
	err = os.WriteFile(configFilePath, configFile, 0644)
	if err != nil {
		return err
	}
	return nil
}

func deleteConfig() error {
	configDir, err := getConfigDir()
	if err != nil {
		return err
	}
	configFilePath := filepath.Join(configDir, "conflux.json")
	return os.Remove(configFilePath)
}

func registerConflux(config *Config) (*RegistrationResponse, error) {
	// Marshal the request body
	body, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	// Create the request
	url := fmt.Sprintf("%s/conflux/register", config.Guardian)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	// Set the Authorization header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.RegistrationToken))
	req.Header.Set("Content-Type", "application/json")

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// if the response is not 200, return an error
	if !(resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK) {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("failed to register conflux: %s: %s", resp.Status, string(body))
	}

	// Read the response body
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse the response body
	var state RegistrationResponse
	err = json.Unmarshal(body, &state)
	if err != nil {
		return nil, err
	}

	return &state, nil
}

func unregisterConflux(config *Config, confluxID string) error {
	// Create the request
	url := fmt.Sprintf("%s/conflux/unregister?conflux_id=%s", config.Guardian, confluxID)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}
	// Set the Authorization header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.RegistrationToken))
	req.Header.Set("Content-Type", "application/json")

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// if the response is not 200, return an error
	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("failed to unregister conflux: %s: %s", resp.Status, string(body))
	}
	return nil
}
