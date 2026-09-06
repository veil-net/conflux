package service

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// run executes a service-manager command and puts its stderr in the error.
//
// The previous conflux logged stderr and returned a bare exit code, which meant
// every systemctl failure reached the user as "exit status 1" with the actual
// explanation somewhere else entirely.
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
