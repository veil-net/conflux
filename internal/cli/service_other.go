//go:build !windows

package cli

import (
	"github.com/veil-net/conflux/internal/account"
	"github.com/veil-net/conflux/internal/daemon"
)

// serveAsService is a Windows concern: systemd and launchd run an ordinary process
// and read its exit code, which is what runSupervisor already is.
func serveAsService(*daemon.Supervisor) (handled bool, code int) { return false, 0 }

// removeAccount deletes the account anchord ran as, when conflux made it.
func removeAccount() error { return account.Remove() }
