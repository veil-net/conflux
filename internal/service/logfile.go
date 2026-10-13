//go:build darwin || freebsd

package service

import (
	"os"

	"github.com/veil-net/conflux/internal/paths"
)

// logFile is where launchd or daemon(8) writes the service's output.
func logFile() string { return paths.Default().LogFile() }

// removeLog deletes it.
func removeLog(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}
