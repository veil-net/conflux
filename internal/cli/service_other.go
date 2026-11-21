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

// removeAccount deletes the accounts anchord ran as -- the installation's, and, with ephemeral, the
// one an ephemeral run gives it -- when conflux made them, stopping whatever runs as each. The BPF
// devices the account was given for the observer go back to root alone first, while there is still
// an account to know them by: a device left in a deleted group is one a group made later with the
// same id could read.
func removeAccount(ephemeral bool) error {
	if err := daemon.RevokeBPF(); err != nil {
		return err
	}

	err := account.Remove()
	if ephemeral {
		err = errors.Join(err, account.RemoveNamed(account.EphemeralName()))
	}

	return err
}
