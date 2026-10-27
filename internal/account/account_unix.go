//go:build !windows

package account

import (
	"errors"
	"fmt"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Lookup is this installation's account, or nil when there is none yet. An account or a
// primary group of that name that conflux did not make is ErrConflict.
func Lookup() (*Account, error) { return lookup(Name()) }

func lookup(name string) (*Account, error) {
	u, err := user.Lookup(name)
	if err != nil {
		var unknown user.UnknownUserError
		if errors.As(err, &unknown) {
			return nil, nil
		}

		return nil, err
	}

	if u.Name != Comment {
		return nil, fmt.Errorf("%w: %s (uid %s) does not carry the comment %q", ErrConflict, name, u.Uid, Comment)
	}

	uid, errU := strconv.Atoi(u.Uid)
	gid, errG := strconv.Atoi(u.Gid)

	if errU != nil || errG != nil || uid == 0 || gid == 0 {
		return nil, fmt.Errorf("%w: %s is uid %s, gid %s", ErrConflict, name, u.Uid, u.Gid)
	}

	// Its own group, so the one thing that group is let into -- passing through the state
	// and run directories to anchord's -- is let to nobody else by the group's name.
	if g, err := user.LookupGroupId(u.Gid); err != nil || g.Name != name {
		return nil, fmt.Errorf("%w: the primary group of %s is gid %s and not a group of its own", ErrConflict, name, u.Gid)
	}

	return &Account{Name: name, UID: uid, GID: gid}, nil
}

// Ensure is this installation's account, made first if there is none. Only root can make
// one, and only root calls this.
//
// Looked up again after a creation that failed, since a second conflux making the same
// account at the same moment fails one of the two over an account that now exists.
func Ensure() (*Account, error) {
	name := Name()

	if a, err := lookup(name); a != nil || err != nil {
		return a, err
	}

	_, err := user.LookupGroup(name)
	groupExists := err == nil

	cmds, err := planCreate(name, groupExists)
	if err != nil {
		return nil, howToCreate(name, cmds, err)
	}

	for _, c := range cmds {
		if err := run(c); err != nil {
			if a, _ := lookup(name); a != nil {
				return a, nil
			}

			return nil, howToCreate(name, cmds, err)
		}
	}

	// macOS's directory service answers for an account a moment after dscl has made it.
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		a, err := lookup(name)
		if a != nil || err != nil {
			return a, err
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%s was created and cannot be found", name)
		}
	}
}

// planCreate is createCommands for this host.
func planCreate(name string, groupExists bool) ([][]string, error) {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("useradd"); err == nil {
			return createCommands("linux", name, true, groupExists, 0), nil
		}

		if _, err := exec.LookPath("adduser"); err == nil {
			return createCommands("linux", name, false, groupExists, 0), nil
		}

		return createCommands("linux", name, true, groupExists, 0),
			errors.New("this host has neither useradd nor busybox's adduser")
	case "darwin":
		taken, err := darwinIDs()
		if err != nil {
			return createCommands("darwin", name, false, groupExists, 0), err
		}

		id, err := freeID(taken)

		return createCommands("darwin", name, false, groupExists, id), err
	default:
		return createCommands(runtime.GOOS, name, false, groupExists, 0), nil
	}
}

// darwinIDs are the user and group ids in use, which dscl lists and nothing picks among.
func darwinIDs() (map[int]bool, error) {
	taken := map[int]bool{}

	for _, kind := range [][]string{{"/Users", "UniqueID"}, {"/Groups", "PrimaryGroupID"}} {
		out, err := exec.Command("dscl", ".", "-list", kind[0], kind[1]).Output()
		if err != nil {
			return nil, fmt.Errorf("dscl . -list %s %s: %w", kind[0], kind[1], err)
		}

		for line := range strings.Lines(string(out)) {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}

			if id, err := strconv.Atoi(fields[len(fields)-1]); err == nil {
				taken[id] = true
			}
		}
	}

	return taken, nil
}

// Remove deletes this installation's account and its group, once nothing runs as it, when
// conflux made it. One conflux did not make is left alone, and so is a group another
// account still uses.
func Remove() error {
	name := Name()

	a, err := lookup(name)

	switch {
	case errors.Is(err, ErrConflict):
		return nil
	case err != nil:
		return err
	case a == nil:
		return nil
	}

	if err := Kill(a.UID); err != nil {
		return err
	}

	_, useraddErr := exec.LookPath("userdel")

	var errs []error

	for i, c := range removeCommands(runtime.GOOS, name, useraddErr == nil) {
		// The group, which userdel and pw take with the account where the host is set to.
		if i > 0 {
			if _, err := user.LookupGroup(name); err != nil {
				continue
			}
		}

		if err := run(c); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func run(argv []string) error {
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput() //nolint:gosec // our own argv
	if err != nil {
		return fmt.Errorf("%s: %w: %s", shell(argv), err, strings.TrimSpace(string(out)))
	}

	return nil
}
