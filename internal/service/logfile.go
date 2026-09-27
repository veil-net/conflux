//go:build darwin || freebsd

package service

import "os"

// removeLog deletes the log file launchd or daemon(8) writes the service's output to.
func removeLog(path string) error {
	if path == "" {
		return nil
	}

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}
