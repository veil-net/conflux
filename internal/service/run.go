package service

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// run executes a service-manager command and puts its stderr in the error, so a
// failure reaches the user as the service manager's explanation rather than as
// "exit status 1".
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)

	var errBuf bytes.Buffer

	cmd.Stderr = &errBuf

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errBuf.String())
		if msg == "" {
			return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}

		return fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), msg)
	}

	return nil
}

// query runs a command for its answer, and treats a non-zero exit as a "no" rather
// than an error -- which is what `systemctl is-active` and friends mean by it.
func query(name string, args ...string) (string, bool) {
	out, err := exec.Command(name, args...).Output()

	return strings.TrimSpace(string(out)), err == nil
}
