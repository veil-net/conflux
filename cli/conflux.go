package cli

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/veil-net/veilnet/logger"
)

var Logger = logger.Logger

type Conflux interface {

	// Run runs the conflux service
	Run() error

	// Install installs the conflux service
	Install() error

	// Start starts the conflux service
	Start() error

	// Stop stops the conflux service
	Stop() error

	// Remove removes the conflux service
	Remove() error

	// Status returns the status of the conflux service
	Status() (bool, error)
}

func NewConflux() Conflux {
	return newConflux()
}

func getConfigDir() (string, error) {
	var configDir string

	switch runtime.GOOS {
case "windows":
		// On Windows, use ProgramData which is accessible by both user and system service
		programData := os.Getenv("ProgramData")
		if programData == "" {
			// Fallback to default if ProgramData is not set
			programData = "C:\\ProgramData"
		}
		configDir = filepath.Join(programData, "conflux")
	case "darwin":
		// On macOS, always use root's config directory so the service (running as root) can read it
		configDir = "/var/root/Library/Application Support/conflux"
	default:
		// On Linux, always use root's config directory so the service (running as root) can read it
		configDir = "/root/.config/conflux"
	}

	return configDir, nil
}
