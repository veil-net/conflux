//go:build !windows

package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// rcEnabled is how a BSD's rc enables conflux at boot: a line in the administrator's rc
// configuration, a command that takes it out, and a question whose yes is that line still there.
// Both BSDs' are here, under no tag of either, so Remove's half is tested where conflux is built.
type rcEnabled struct {
	file, line    string   // the file the line is in, and what it does there
	disable, left []string // the command that takes it out; the question that finds it there
}

var (
	// sysrc -x takes the variable out of rc.conf, and refuses one that is not set; -n prints a
	// set one's value, whatever it is, and exits 1 for one that is not.
	freebsdEnabled = rcEnabled{
		"rc.conf", "sets " + rcName + "_enable",
		[]string{"sysrc", "-x", rcName + "_enable"}, []string{"sysrc", "-n", rcName + "_enable"},
	}

	// rcctl(8): disable takes the service out of rc.conf.local, whether or not its script is
	// there; get ... status exits 0 for one that is enabled and 1 for one that is not, and 2 for
	// one whose script is not there, which says nothing of the line.
	openbsdEnabled = rcEnabled{
		"rc.conf.local", "enables " + rcName,
		[]string{"rcctl", "disable", rcName}, []string{"rcctl", "get", rcName, "status"},
	}
)

// remove takes conflux's line out, then asks whether it is still there, and deletes script once
// it is not. One that is, is said, with whatever the command answered: it is conflux, left on the
// machine, as a file systemd's Remove could not remove is. The command's answer is forgiven once
// the line is gone, which is what was asked for: sysrc -x refuses a variable that was never set.
//
// The script stays while the line does, so the next uninstall can ask again: rcctl answers
// nothing for a service whose script is not there. Where the question cannot be answered, the
// command's own answer stands: a refusal is said, and a line it took out, or none there, is gone.
func (e rcEnabled) remove(script string) error {
	disable := run(e.disable[0], e.disable[1:]...)

	asked := strings.Join(e.left, " ")

	switch left, out, err := e.there(); {
	case err != nil && disable != nil:
		return errors.Join(fmt.Errorf("could not ask whether %s still %s (%s: %w)", e.file, e.line, asked, err), disable)
	case left:
		if out != "" {
			asked += ": " + out
		}

		return errors.Join(fmt.Errorf("%s still %s (%s)", e.file, e.line, asked), disable)
	}

	if err := os.Remove(script); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// there asks whether the line is there, and says what the question printed. An exit of 0 is
// yes and 1 is no; anything else -- 2 and above, which rcctl answers for a service whose script
// it cannot find, or a question that did not run -- answers neither, and is the error, with
// what the question said on stderr.
func (e rcEnabled) there() (bool, string, error) {
	b, err := exec.Command(e.left[0], e.left[1:]...).Output()
	out := strings.TrimSpace(string(b))

	var exit *exec.ExitError

	switch {
	case err == nil:
		return true, out, nil
	case errors.As(err, &exit) && exit.ExitCode() == 1:
		return false, out, nil
	case errors.As(err, &exit) && len(strings.TrimSpace(string(exit.Stderr))) > 0:
		return false, out, errors.New(strings.TrimSpace(string(exit.Stderr)))
	default:
		return false, out, err
	}
}
