//go:build !linux && !windows

package daemon

import (
	"os/exec"
	"syscall"
)

// canGive has nothing to check beyond root here, which dropTo already has: macOS and the
// BSDs give root everything a drop needs, and anchord is given no capability.
func canGive(*Privilege) string { return "" }

func withCaps(*syscall.SysProcAttr, []string) {}

func startProcess(cmd *exec.Cmd, _ Privilege) error { return cmd.Start() }
