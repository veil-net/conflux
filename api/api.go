package api

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/gofiber/fiber/v2"
	hcplugin "github.com/hashicorp/go-plugin"
	"github.com/veil-net/conflux/anchor"
)

var handshakeConfig = hcplugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "ANCHOR_PLUGIN",
	MagicCookieValue: "anchor",
}

var pluginMap = map[string]hcplugin.Plugin{
	"anchor": &anchor.AnchorPlugin{},
}

type API struct {
	config          *Config
	app             *fiber.App
	plugin          *hcplugin.Client
	anchorInterface anchor.Anchor

	mu   sync.Mutex
	once sync.Once
}

func NewAPI() *API {
	app := fiber.New()
	return &API{
		app: app,
	}
}

func (a *API) initializePlugin() error {
	if a.plugin != nil {
		a.plugin.Kill()
		a.anchorInterface = nil
		a.plugin = nil
	}
	// Create the plugin
	err := a.anchor()
	if err != nil {
		return err
	}
	return nil
}

func (a *API) resetPlugin() error {
	if a.plugin != nil {
		a.plugin.Kill()
		a.anchorInterface = nil
		a.plugin = nil
	}
	return nil
}

func (a *API) Run() {
	// Create the anchor interface
	err := a.initializePlugin()
	if err != nil {
		Logger.Sugar().Fatalf("failed to create anchor interface: %v", err)
	}

	// Load existing configuration
	existingConfig, err := loadConfig()
	if err == nil {
		Logger.Sugar().Infof("loaded existing configuration: Conflux Tag: %s, Portal: %t", existingConfig.Tag, existingConfig.Portal)
		// Register the conflux
		registrationResponse, err := registerConflux(existingConfig)
		if err == nil {
			// Create the anchor
			err = a.anchorInterface.CreateAnchor()
			if err != nil {
				Logger.Sugar().Fatalf("failed to create anchor: %v", err)
			}
			// Start the anchor
			err = a.anchorInterface.StartAnchor(existingConfig.Guardian, existingConfig.Veil, existingConfig.VeilPort, registrationResponse.Token, existingConfig.Portal)
			if err == nil {
				// Create the TUN device
				err = a.anchorInterface.CreateTUN("veilnet", 1500)
				if err == nil {
					err = a.anchorInterface.LinkWithTUN()
					if err == nil {
						a.config = existingConfig
					} else {
						a.resetPlugin()
						Logger.Sugar().Warnf("failed to link anchor with TUN device: %v", err)
					}
				} else {
					a.resetPlugin()
					Logger.Sugar().Warnf("failed to create TUN device: %v", err)
				}
			} else {
				a.resetPlugin()
				Logger.Sugar().Warnf("failed to start anchor: %v", err)
			}
		} else {
			Logger.Sugar().Warnf("failed to register conflux instance: %v", err)
		}
	} else {
		Logger.Sugar().Warnf("failed to load configuration: %v", err)
	}

	// Register the API routes
	a.app.Post("/register", a.handleRegister)
	a.app.Delete("/unregister", a.handleUnregister)
	a.app.Post("/up", a.handleUP)
	a.app.Delete("/down", a.handleDown)
	a.app.Get("/health", a.handleHealth)

	// Start the fiber app
	go func() {
		if err := a.app.Listen("127.0.0.1:1993"); err != nil {
			Logger.Sugar().Fatalf("VeilNet Conflux service has stopped: %v", err)
		}
	}()

	Logger.Sugar().Info("VeilNet Conflux service has started on port 1993")
}

func (a *API) Stop() {
	a.once.Do(func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.anchorInterface != nil {
			a.anchorInterface.StopAnchor()
			a.anchorInterface.DestroyAnchor()
			a.anchorInterface.DestroyTUN()
		}
		if a.app != nil {
			a.app.Shutdown()
		}
	})
}

func (a *API) handleRegister(c *fiber.Ctx) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Check if the service is already registered
	if a.config != nil && a.anchor != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"detail": "conflux already registered",
		})
	}

	// Parse the request body
	body := c.Body()
	config := &Config{}
	err := json.Unmarshal(body, config)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"detail": "failed to parse request body",
		})
	}
	// Register the conflux
	registrationResponse, err := registerConflux(config)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"detail": fmt.Sprintf("failed to register conflux: %v", err),
		})
	}
	// Initialize the plugin
	err = a.initializePlugin()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"detail": fmt.Sprintf("failed to initialize plugin: %v", err),
		})
	}
	// Create the anchor
	err = a.anchorInterface.CreateAnchor()
	if err != nil {
		a.resetPlugin()
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"detail": fmt.Sprintf("failed to create anchor: %v", err),
		})
	}
	// Start the anchor
	err = a.anchorInterface.StartAnchor(config.Guardian, config.Veil, config.VeilPort, registrationResponse.Token, config.Portal)
	if err != nil {
		a.resetPlugin()
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"detail": fmt.Sprintf("failed to start anchor: %v", err),
		})
	}
	// Create the TUN device
	err = a.anchorInterface.CreateTUN("veilnet", 1500)
	if err != nil {
		a.resetPlugin()
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"detail": fmt.Sprintf("failed to create TUN device: %v", err),
		})
	}
	// Attach the anchor to the TUN device
	err = a.anchorInterface.LinkWithTUN()
	if err != nil {
		a.resetPlugin()
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"detail": fmt.Sprintf("failed to attach anchor to TUN device: %v", err),
		})
	}
	a.config = config
	// Save the configuration
	err = saveConfig(config)
	if err != nil {
		Logger.Sugar().Warnf("failed to save configuration: %v", err)
	}
	return c.SendStatus(fiber.StatusOK)
}

func (a *API) handleUnregister(c *fiber.Ctx) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.config == nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"detail": "no configuration found, this instance is not registered",
		})
	}

	// Delete the configuration file
	err := deleteConfig()
	if err != nil {
		Logger.Sugar().Warnf("failed to delete configuration file: %v", err)
	}

	if a.anchor != nil {
		// Get the conflux ID
		confluxID, err := a.anchorInterface.GetID()
		if err != nil {
			Logger.Sugar().Errorf("failed to get conflux ID: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"detail": fmt.Sprintf("failed to get conflux ID: %v", err),
			})
		}
		// Unregister the conflux
		err = unregisterConflux(a.config, confluxID)
		if err != nil {
			Logger.Sugar().Errorf("failed to unregister conflux: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"detail": fmt.Sprintf("failed to unregister conflux: %v", err),
			})
		}
		// Stop the anchor plugin
		a.resetPlugin()
	}
	// Clear the config
	a.config = nil
	return c.SendStatus(fiber.StatusOK)
}

func (a *API) handleUP(c *fiber.Ctx) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Parse the request body
	body := c.Body()
	config := &ConfluxConfig{}
	err := json.Unmarshal(body, config)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"detail": "failed to parse request body",
		})
	}
	// Initialize the plugin
	err = a.initializePlugin()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"detail": fmt.Sprintf("failed to initialize plugin: %v", err),
		})
	}
	// Create the anchor
	err = a.anchorInterface.CreateAnchor()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"detail": fmt.Sprintf("failed to create anchor: %v", err),
		})
	}
	// Start the anchor
	err = a.anchorInterface.StartAnchor(config.Guardian, config.Veil, config.VeilPort, config.Token, config.Portal)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"detail": fmt.Sprintf("failed to start anchor: %v", err),
		})
	}
	// Create the TUN device
	err = a.anchorInterface.CreateTUN("veilnet", 1500)
	if err != nil {
		a.resetPlugin()
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"detail": fmt.Sprintf("failed to create TUN device: %v", err),
		})
	}
	// Attach the anchor to the TUN device
	err = a.anchorInterface.LinkWithTUN()
	if err != nil {
		a.resetPlugin()
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"detail": fmt.Sprintf("failed to link anchor with TUN device: %v", err),
		})
	}
	return c.SendStatus(fiber.StatusOK)
}

func (a *API) handleDown(c *fiber.Ctx) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Reset the plugin
	err := a.resetPlugin()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"detail": fmt.Sprintf("failed to reset plugin: %v", err),
		})
	}
	return c.SendStatus(fiber.StatusOK)
}

func (a *API) handleHealth(c *fiber.Ctx) error {
	return c.SendStatus(fiber.StatusOK)
}
