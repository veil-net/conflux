//go:build !windows

package cli

import (
	"errors"

	"github.com/veil-net/conflux/internal/account"
	"github.com/veil-net/conflux/internal/daemon"
)

// serveAsService is a Windows concern: systemd and launchd run an ordinary process
// and read its exit code, which is what runSupervisor already is.
func serveAsService(*daemon.Supervisor) (handled bool, code int) { return false, 0 }

// removeAccount deletes the accounts anchord ran as -- the installation's, and the one an
// ephemeral run gives it -- when conflux made them. The BPF devices the account was given
// for the observer go back to root alone first, while there is still an account to know them
// by: a device left in a deleted group is one a group made later with the same id could read.
func removeAccount() error {
	if err := daemon.RevokeBPF(); err != nil {
		return err
	}

	return errors.Join(account.Remove(), account.RemoveNamed(account.EphemeralName()))
}
