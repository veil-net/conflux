//go:build !windows

package paths

import (
	"fmt"
	"os"
	"syscall"
)

// Restrict and Trusted are Windows's. Here a mode set on the descriptor and a 0700
// directory that belongs to whoever runs conflux are the whole of it, and secure is
// what makes sure of the second.

// Restrict is a no-op here.
func Restrict(string, bool) error { return nil }

// Trusted is always true here.
func Trusted(string) bool { return true }

// secure refuses a root another account owns, and narrows one of conflux's own that
// something left wider than 0700, or than the 0710 that lets anchord's account through.
//
// MkdirAll creates at 0700 and leaves a directory that already exists exactly as it
// found it, so without this an /etc/conflux somebody made at 0755 would hold the
// manifest in a traversable directory, and a CONFLUX_DIR another user made would hold
// the binary root runs at boot where that user can replace it. The owner decides, as on
// Windows: one that is not the account running conflux did not get its directory from
// conflux, and whatever it put there is not used. The refusal comes before any change.
func secure(dir string) error { return secureAs(dir, os.Geteuid()) }

// secureAs is secure for a given effective uid, so the refusals can be tested without
// another account.
func secureAs(dir string, euid int) error {
	// A root that is a symlink is held to the same rule as what it points at: one another
	// account planted would otherwise lead straight past the check into a directory of
	// theirs, or of the system's.
	link, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}

	if err := ownedBy(dir, link, euid); err != nil {
		return err
	}

	fi := link
	if link.Mode()&os.ModeSymlink != 0 {
		if fi, err = os.Stat(dir); err != nil {
			return fmt.Errorf("read %s: %w", dir, err)
		}

		if err := ownedBy(dir, fi, euid); err != nil {
			return err
		}
	}

	// 0710 -- its group may pass through and list nothing -- is how the supervisor lets
	// anchord's account reach the few things in the state and run directories that anchord
	// runs or reads. ownedBy has just shown the directory to be this account's own, and only
	// its owner can have given it that group and that mode, so it is left as it is.
	if mode := fi.Mode().Perm(); mode == 0o700 || mode == 0o710 {
		return nil
	}

	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("narrow %s to 0700: %w", dir, err)
	}

	return nil
}

func ownedBy(dir string, fi os.FileInfo, euid int) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("read the owner of %s: no ownership on this filesystem", dir)
	}

	switch owner := int(st.Uid); {
	case owner == euid:
		return nil
	case owner == 0:
		return fmt.Errorf("%s belongs to root, and conflux is not running as root.\n"+
			"  Run this again as root", dir)
	default:
		return fmt.Errorf(
			"%s belongs to uid %d and conflux runs as uid %d, so conflux did not create it and will not "+
				"use what is in it.\n  Remove it, then run this again", dir, owner, euid)
	}
}
