// Package anchor provides config, registration, and anchor subprocess/client helpers for conflux.
package anchor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	pb "github.com/veil-net/conflux/proto"
)

// TracerConfig holds OTLP/tracing settings (enabled, endpoint, TLS, certs).
type TracerConfig struct {
	Enabled  bool   `json:"enabled" validate:"required"`
	Endpoint string `json:"endpoint" validate:"required"`
	UseTLS   bool   `json:"use_tls" validate:"required"`
	Insecure bool   `json:"insecure" validate:"required"`
	CAFile   string `json:"ca_file" validate:"required"`
	CertFile string `json:"cert_file" validate:"required"`
	KeyFile  string `json:"key_file" validate:"required"`
}

type IDPConfig struct {
	JWT string `json:"jwt" validate:"required"`
	JWKS_url string `json:"jwks_url" validate:"required"`
	Audience string `json:"audience" validate:"required"`
	Issuer string `json:"issuer" validate:"required"`
}

// ConfluxConfig holds conflux runtime config (ID, token, guardian, rift/portal, IP, taints, tracer).
type ConfluxConfig struct {
	ConfluxID string        `json:"conflux_id" validate:"required"`
	Token     string        `json:"conflux_token" validate:"required"`
	Guardian  string        `json:"guardian" validate:"required"`
	Rift      bool          `json:"rift" validate:"required"`
	Portal    bool          `json:"portal" validate:"required"`
	IP        string        `json:"ip" validate:"required"`
	Taints    []string      `json:"taints"`
	Tracer    *TracerConfig `json:"tracer"`
}

// ResgitrationRequest is the request payload for conflux registration (token, guardian, tag, JWT/JWKS, etc.).
type ResgitrationRequest struct {
	RegistrationToken string `json:"registration_token" validate:"required"`
	Guardian          string `json:"guardian" validate:"required"`
	Tag               string `json:"tag"`
	JWT               string `json:"jwt"`
	JWKS_url          string `json:"jwks_url"`
	Audience          string `json:"audience"`
	Issuer            string `json:"issuer"`
}

// RegistrationResponse is the response with ConfluxID and token.
type RegistrationResponse struct {
	ConfluxID string `json:"conflux_id" validate:"required"`
	Token     string `json:"token" validate:"required"`
}

// GetConfigDir returns the OS-specific config directory for conflux.
//
// Inputs: none.
//
// Outputs:
//   - configDir: string. The config directory path.
//   - err: error. Non-nil if the directory cannot be determined.
func GetConfigDir() (string, error) {
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

// LoadConfig loads ConfluxConfig from the config file.
//
// Inputs: none.
//
// Outputs:
//   - config: *ConfluxConfig. The loaded config.
//   - err: error. Non-nil if the file is missing or invalid.
func LoadConfig() (*ConfluxConfig, error) {
	configDir, err := GetConfigDir()
	if err != nil {
		return nil, err
	}
	configFilePath := filepath.Join(configDir, "conflux.json")
	configFile, err := os.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}
	config := &ConfluxConfig{}
	err = json.Unmarshal(configFile, config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

// SaveConfig writes ConfluxConfig to the config file.
//
// Inputs:
//   - config: *ConfluxConfig. The conflux config to write.
//
// Outputs:
//   - err: error. Non-nil if the file cannot be written.
func SaveConfig(config *ConfluxConfig) error {
	configDir, err := GetConfigDir()
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

// DeleteConfig removes the config file.
//
// Inputs: none.
//
// Outputs:
//   - err: error. Non-nil if the file cannot be removed.
func DeleteConfig() error {
	configDir, err := GetConfigDir()
	if err != nil {
		return err
	}
	configFilePath := filepath.Join(configDir, "conflux.json")
	return os.Remove(configFilePath)
}

// RegisterConflux registers a conflux with the guardian and returns RegistrationResponse.
//
// Inputs:
//   - config: *ResgitrationRequest. Registration request (token, guardian, tag, JWT/JWKS, etc.).
//
// Outputs:
//   - *RegistrationResponse. The registration response (ConfluxID, token).
//   - err: error. Non-nil if the guardian request fails.
func RegisterConflux(config *ResgitrationRequest) (*RegistrationResponse, error) {
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

// UnregisterConflux unregisters the conflux with the guardian using the registration token.
//
// Inputs:
//   - registrationToken: string. Token used to authenticate.
//   - config: *ConfluxConfig. Current conflux config (Guardian, ConfluxID).
//
// Outputs:
//   - err: error. Non-nil if the guardian request fails.
func UnregisterConflux(registrationToken string, config *ConfluxConfig) error {
	// Create the request
	url := fmt.Sprintf("%s/conflux/unregister?conflux_id=%s", config.Guardian, config.ConfluxID)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}
	// Set the Authorization header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", registrationToken))
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

// StartConflux registers the conflux, starts the anchor subprocess, creates a gRPC client, and starts the anchor.
//
// Inputs:
//   - token, ip, tag, jwt, jwks_url, audience, issuer: string. Registration/identity args.
//   - tracer: *TracerConfig. Optional OTLP config.
//
// Outputs:
//   - subprocess: *exec.Cmd. The started anchor subprocess.
//   - anchor: pb.AnchorClient. The gRPC client.
//   - err: error. Non-nil if registration or anchor start fails.
func StartConflux(token string, ip string, tag string, idp *IDPConfig, tracer *TracerConfig) (subprocess *exec.Cmd, anchor pb.AnchorClient, err error) {


	guardian := "https://guardian.veilnet.app"

	// Parse the command
	registrationRequest := &ResgitrationRequest{
		RegistrationToken: token,
		Guardian:          guardian,
		Tag:               tag,
	}

	if idp != nil {
		registrationRequest.JWT = idp.JWT
		registrationRequest.JWKS_url = idp.JWKS_url
		registrationRequest.Audience = idp.Audience
		registrationRequest.Issuer = idp.Issuer
	}

	// Register the conflux
	registrationResponse, err := RegisterConflux(registrationRequest)
	if err != nil {
		return nil, nil, err
	}

	// Initialize the anchor plugin
	subprocess, err = NewAnchor()
	if err != nil {
		return nil, nil, err
	}

	// Wait for the subprocess to start
	time.Sleep(1 * time.Second)

	// Create a gRPC client connection
	anchor, err = NewAnchorClient()
	if err != nil {
		subprocess.Process.Kill()
		return nil, nil, err
	}

	var tracerConfig *pb.TracerConfig
	if tracer == nil {
		tracerConfig = &pb.TracerConfig{
			Enabled: false,
		}
	} else {
		tracerConfig = &pb.TracerConfig{
			Enabled:  tracer.Enabled,
			Endpoint: tracer.Endpoint,
			UseTls:   tracer.UseTLS,
			Insecure: tracer.Insecure,
			Ca:       tracer.CAFile,
			Cert:     tracer.CertFile,
			Key:      tracer.KeyFile,
		}
	}

	// Start the anchor
	_, err = anchor.StartAnchor(context.Background(), &pb.StartAnchorRequest{
		GuardianUrl: guardian,
		AnchorToken: registrationResponse.Token,
		Ip:          ip,
		Tracer:      tracerConfig,
	})
	if err != nil {
		subprocess.Process.Kill()
		return nil, nil, err
	}
	return subprocess, anchor, nil
}
