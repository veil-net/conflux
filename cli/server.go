package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/veil-net/veilnet"
)

type API struct {
	conflux Conflux
	server  *echo.Echo

	mu sync.Mutex
}

func newAPI(conflux Conflux) *API {
	return &API{
		conflux: conflux,
	}
}

func (api *API) Run() error {

	// Create the server
	api.server = echo.New()

	// Register routes
	api.server.POST("/up", api.up)
	api.server.POST("/down", api.down)
	api.server.POST("/register", api.register)
	api.server.POST("/unregister", api.unregister)
	// Create a context for the server
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Start server
	go func() {
		if err := api.server.Start("127.0.0.1:1993"); err != nil && err != http.ErrServerClosed {
			api.conflux.StopVeilNet()
			veilnet.Logger.Sugar().Fatalf("Conflux service encountered an error: %v", err)
		}
	}()
	// Load existing registration data
	var register Register
	tmpDir, err := os.UserConfigDir()
	if err == nil {
		confluxDir := filepath.Join(tmpDir, "conflux")
		confluxFile := filepath.Join(confluxDir, "conflux.json")
		registrationDataFile, err := os.ReadFile(confluxFile)
		if err == nil {
			json.Unmarshal(registrationDataFile, &register)
		}
	} else {
		guardian := os.Getenv("VEILNET_GUARDIAN")
		token := os.Getenv("VEILNET_REGISTRATION_TOKEN")
		tag := os.Getenv("VEILNET_CONFLUX_TAG")
		cidr := os.Getenv("VEILNET_CONFLUX_CIDR")
		portal := os.Getenv("VEILNET_PORTAL") == "true"
		teams := os.Getenv("VEILNET_CONFLUX_TEAMS")
		register = Register{
			Tag:      tag,
			Cidr:     cidr,
			Guardian: guardian,
			Token:    token,
			Portal:   portal,
			Teams:    teams,
		}
	}
	if register.Guardian != "" || register.Token != "" {
		go func() {
			veilnet.Logger.Sugar().Infof("registering conflux from loaded registration data or environment variables")
			time.Sleep(1 * time.Second)
			err := register.Run()
			if err != nil {
				veilnet.Logger.Sugar().Errorf("failed to register conflux: %v", err)
			}
		}()
	}
	// Wait for interrupt signal to gracefully shut down the server with a timeout of 10 seconds.
	<-ctx.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := api.server.Shutdown(ctx); err != nil {
		veilnet.Logger.Sugar().Fatalf("shutting down the server: %v", err)
	}
	// Stop the veilnet
	api.conflux.StopVeilNet()

	return nil
}

func (api *API) up(c echo.Context) error {
	api.mu.Lock()
	defer api.mu.Unlock()
	var request Up
	if err := c.Bind(&request); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"details": "Invalid request"})
	}

	if request.Guardian == "" {
		return c.JSON(http.StatusBadRequest, echo.Map{"details": "Guardian URL is required"})
	}

	if request.Token == "" {
		return c.JSON(http.StatusBadRequest, echo.Map{"details": "Token is required"})
	}

	if err := api.conflux.StartVeilNet(request.Guardian, request.Token, request.Portal); err != nil {
		api.conflux.StopVeilNet()
		return c.JSON(http.StatusInternalServerError, echo.Map{"details": "Failed to start VeilNet"})
	}

	return c.JSON(http.StatusOK, echo.Map{"details": "VeilNet started"})
}

func (api *API) down(c echo.Context) error {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.conflux.StopVeilNet()

	return c.JSON(http.StatusOK, echo.Map{"details": "VeilNet stopped"})
}

type ConfluxToken struct {
	ConfluxID string `json:"conflux_id"`
	Token     string `json:"token"`
}

func (api *API) register(c echo.Context) error {
	api.mu.Lock()
	defer api.mu.Unlock()
	var request Register
	if err := c.Bind(&request); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"details": "Invalid request"})
	}

	// Parse the Guardian URL
	path := fmt.Sprintf("%s/conflux/register", request.Guardian)

	// Marshal the request body
	body, err := json.Marshal(request)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"details": "Failed to marshal request body"})
	}

	// Create the request
	req, err := http.NewRequest("POST", path, bytes.NewBuffer(body))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"details": "Failed to create register request"})
	}

	// Set the Authorization header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", request.Token))
	req.Header.Set("Content-Type", "application/json")

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"details": fmt.Sprintf("Failed to make register request %v", err)})
	}
	defer resp.Body.Close()

	// Read the response body
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"details": "Failed to read register response body"})
	}

	if !(resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK) {
		return c.JSON(http.StatusInternalServerError, echo.Map{"details": fmt.Sprintf("register failed with status %d: %s", resp.StatusCode, string(body))})
	}

	// Parse the response body
	var confluxToken ConfluxToken
	err = json.Unmarshal(body, &confluxToken)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"details": "Failed to parse register response"})
	}

	// Write the registration data to file
	tmpDir, err := os.UserConfigDir()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"details": "Failed to get user config directory"})
	}
	confluxDir := filepath.Join(tmpDir, "conflux")
	os.MkdirAll(confluxDir, 0755)
	confluxFile := filepath.Join(confluxDir, "conflux.json")
	request.ID = confluxToken.ConfluxID
	resitrationData, err := json.Marshal(request)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"details": "Failed to marshal registration data"})
	}
	err = os.WriteFile(confluxFile, resitrationData, 0644)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"details": "Failed to write registration data"})
	}
	veilnet.Logger.Sugar().Infof("Registration data written to %s", confluxFile)

	// Stop the current VeilNet
	api.conflux.StopVeilNet()

	// Start the VeilNet
	err = api.conflux.StartVeilNet(request.Guardian, confluxToken.Token, request.Portal)
	if err != nil {
		api.conflux.StopVeilNet()
		return c.JSON(http.StatusInternalServerError, echo.Map{"details": fmt.Sprintf("Failed to start VeilNet: %v", err)})
	}

	return c.JSON(http.StatusOK, echo.Map{"details": "VeilNet started"})
}

func (api *API) unregister(c echo.Context) error {
	api.mu.Lock()
	defer api.mu.Unlock()

	// Load the registration data
	tmpDir, err := os.UserConfigDir()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to get user config directory: %v", err)
	}
	confluxDir := filepath.Join(tmpDir, "conflux")
	confluxFile := filepath.Join(confluxDir, "conflux.json")
	registrationData, err := os.ReadFile(confluxFile)
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to read registration data: %v", err)
	}
	var register Register
	err = json.Unmarshal(registrationData, &register)
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to unmarshal registration data: %v", err)
	}

	path := fmt.Sprintf("%s/conflux/unregister?conflux_id=%s", register.Guardian, register.ID)
	req, err := http.NewRequest("DELETE", path, nil)
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to create unregister request: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", register.Token))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to make unregister request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to read unregister response body: %v", err)
		}
		veilnet.Logger.Sugar().Errorf("unregister failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Stop the current VeilNet
	api.conflux.StopVeilNet()

	// Remove the conflux file
	err = os.Remove(confluxFile)
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to remove conflux file: %v", err)
	}
	return c.JSON(http.StatusOK, echo.Map{"details": "VeilNet unregistered"})
}