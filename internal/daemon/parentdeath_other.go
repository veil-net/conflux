//go:build !linux

package daemon

import "syscall"

// setParentDeath is Linux's: nothing else can ask at the start. Windows ends anchord with
// its job object however this process ends; macOS and the BSDs leave it, for the next
// ephemeral run to stop.
func setParentDeath(*syscall.SysProcAttr) {}
