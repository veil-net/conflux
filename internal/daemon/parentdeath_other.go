//go:build !linux

package daemon

import "syscall"

// setParentDeath is Linux's, the one platform an ephemeral run, which asks for it, runs on.
func setParentDeath(*syscall.SysProcAttr) {}
