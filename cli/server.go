package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
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
	api.server.GET("/metrics/:name", api.metrics)
	// Create a context for the server
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Start server
	go func() {
		if err := api.server.Start(":1993"); err != nil && err != http.ErrServerClosed {
			veilnet.Logger.Sugar().Fatalf("shutting down the server: %v", err)
		}
	}()
	// Load existing registration data
	tmpDir, err := os.UserConfigDir()
	if err != nil {
		veilnet.Logger.Sugar().Fatalf("failed to get user config directory: %v", err)
	}
	confluxDir := filepath.Join(tmpDir, "conflux")
	confluxFile := filepath.Join(confluxDir, "conflux.json")
	registrationDataFile, err := os.ReadFile(confluxFile)
	if err == nil {
		veilnet.Logger.Sugar().Infof("loading registration data from %s", confluxFile)
		var register Register
		err = json.Unmarshal(registrationDataFile, &register)
		if err != nil {
			veilnet.Logger.Sugar().Warnf("failed to unmarshal registration data from %s: %v", confluxFile, err)
		} else {
			for {
				err = register.Run()
				if err != nil {
					continue
				}
				break
			}
		}
	} else {
		veilnet.Logger.Sugar().Infof("loading registration data from environment variable")
		guardian := os.Getenv("VEILNET_GUARDIAN")
		token := os.Getenv("VEILNET_REGISTRATION_TOKEN")
		tag := os.Getenv("VEILNET_CONFLUX_TAG")
		cidr := os.Getenv("VEILNET_CONFLUX_CIDR")
		portal := os.Getenv("VEILNET_PORTAL") == "true"
		subnets := os.Getenv("VEILNET_CONFLUX_SUBNETS")
		register := Register{
			Tag:      tag,
			Cidr:     cidr,
			Guardian: guardian,
			Token:    token,
			Portal:   portal,
			Subnets:  subnets,
		}
		if guardian == "" || token == "" {
			veilnet.Logger.Sugar().Errorf("VEILNET_GUARDIAN and VEILNET_REGISTRATION_TOKEN are required")
		} else {
			for {
				err = register.Run()
				if err != nil {
					continue
				}
				break
			}
		}
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

	// Add subnets to the conflux
	if request.Subnets != "" {
		// Split the subnets by comma
		subnets := strings.Split(request.Subnets, ",")
		for _, subnet := range subnets {
			// Parse the subnet
			_, ipnet, err := net.ParseCIDR(subnet)
			if err != nil {
				veilnet.Logger.Sugar().Warnf("failed to parse subnet %s: %v", subnet, err)
				continue
			}
			// Marshal the request body
			body, err := json.Marshal(map[string]string{"conflux_id": confluxToken.ConfluxID, "subnet": subnet, "tag": request.Tag})
			if err != nil {
				veilnet.Logger.Sugar().Warnf("failed to marshal request body: %v", err)
				continue
			}
			// Create the request
			path := fmt.Sprintf("%s/conflux/register/local-network", request.Guardian)
			req, err := http.NewRequest("POST", path, bytes.NewBuffer(body))
			if err != nil {
				veilnet.Logger.Sugar().Warnf("failed to create local network request: %v", err)
				continue
			}
			// Set the Authorization header
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", request.Token))
			req.Header.Set("Content-Type", "application/json")
			// Make the request
			resp, err := client.Do(req)
			if err != nil {
				veilnet.Logger.Sugar().Warnf("failed to add local network: %v", err)
				continue
			}
			defer resp.Body.Close()
			// Read the response body
			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					veilnet.Logger.Sugar().Warnf("failed to read local network response body: %v", err)
					continue
				}
				veilnet.Logger.Sugar().Warnf("failed to add local network: %s: %s", resp.Status, string(body))
				continue
			}
			veilnet.Logger.Sugar().Infof("added local network %s to conflux %s", ipnet.String(), confluxToken.ConfluxID)
		}
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
		return c.JSON(http.StatusInternalServerError, echo.Map{"details": "Failed to start VeilNet"})
	}

	return c.JSON(http.StatusOK, echo.Map{"details": "VeilNet started"})
}

func (api *API) unregister(c echo.Context) error {
	api.mu.Lock()
	defer api.mu.Unlock()

	// Load the registration data
	tmpDir, err := os.UserConfigDir()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"details": "Failed to get user config directory"})
	}
	confluxDir := filepath.Join(tmpDir, "conflux")
	confluxFile := filepath.Join(confluxDir, "conflux.json")
	registrationData, err := os.ReadFile(confluxFile)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"details": "Failed to read registration data"})
	}
	var register Register
	err = json.Unmarshal(registrationData, &register)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"details": "Failed to unmarshal registration data"})
	}

	path := fmt.Sprintf("%s/conflux/unregister?conflux_id=%s", register.Guardian, register.ID)
	req, err := http.NewRequest("DELETE", path, nil)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"details": "Failed to create unregister request"})
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", register.Token))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"details": "Failed to make unregister request"})
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, echo.Map{"details": "Failed to read unregister response body"})
		}
		return c.JSON(http.StatusInternalServerError, echo.Map{"details": fmt.Sprintf("unregister failed with status %d: %s", resp.StatusCode, string(body))})
	}

	// Stop the current VeilNet
	api.conflux.StopVeilNet()

	// Remove the conflux file
	err = os.Remove(confluxFile)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"details": "Failed to remove conflux file"})
	}
	return c.JSON(http.StatusOK, echo.Map{"details": "VeilNet unregistered"})
}

func (api *API) metrics(c echo.Context) error {
	api.mu.Lock()
	defer api.mu.Unlock()
	name := c.Param("name")
	metrics := api.conflux.Metrics(name)
	return c.JSON(http.StatusOK, echo.Map{"metrics": metrics})
}
